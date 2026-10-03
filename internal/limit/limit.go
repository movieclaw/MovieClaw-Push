// Package limit 执行推送限额，并按「实例 × 天」汇总计数。
//
// 限额只基于中继自己能核实的维度（条数、类型、优先级、设备数），不依赖实例自报的信息。
// 两类计数分开存放：
//   - 按设备的计数（每台设备每天几条，覆盖所有实例）只放内存，重启清零可以接受；
//   - 按「实例 × 天」的汇总写进本地 SQLite（usage.db），api 每小时通过 /admin/v1/usage
//     拉走，本地保留 7 天。汇总里只有数字：不存设备令牌，也不存令牌哈希。
//
// 日界按 UTC 划分，限额在 UTC 零点（北京时间 8:00）重置。
package limit

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/movieclaw/movieclaw-push/protocol"
)

// RetentionDays 是本地保留的天数（含今天）。
const RetentionDays = 7

const dayLayout = "2006-01-02"

// Attempt 是一条准备发给苹果的推送。
type Attempt struct {
	Device       protocol.DeviceKey
	Type         string
	Priority     int
	Interruption string
}

// Denial 是超出限额。
type Denial struct {
	// Limit 是触发的限制名，和令牌里 lim 的键一致，如 day、device_day。
	Limit      string
	Max        int64
	RetryAfter time.Duration
	// Message 是给人看的中文说明，实例原样显示在设置页，新的限制类型老实例也能看懂。
	Message string
}

// Stats 是一个实例一天的汇总。
type Stats struct {
	Instance     string
	Day          string
	Count        int64
	Type         map[string]int64
	Priority     map[string]int64
	Interruption map[string]int64
	Failures     map[string]int64
	Hours        [24]int64
	Devices      HLL
	dirty        bool
}

func newStats(instance, day string) *Stats {
	return &Stats{
		Instance:     instance,
		Day:          day,
		Type:         map[string]int64{},
		Priority:     map[string]int64{},
		Interruption: map[string]int64{},
		Failures:     map[string]int64{},
	}
}

// DayUsage 是 /admin/v1/usage 返回的一行：一个实例一天的汇总。
type DayUsage struct {
	Instance     string           `json:"instance"`
	Day          string           `json:"day"`
	Count        int64            `json:"count"`
	Type         map[string]int64 `json:"type"`
	Priority     map[string]int64 `json:"priority"`
	Interruption map[string]int64 `json:"interruption"`
	Devices      int64            `json:"devices"`
	Failures     map[string]int64 `json:"failures"`
	Hours        [24]int64        `json:"hours"`
	PeakHour     int64            `json:"peak_hour"`
}

func (st *Stats) usage() DayUsage {
	u := DayUsage{
		Instance: st.Instance, Day: st.Day, Count: st.Count,
		Type: st.Type, Priority: st.Priority, Interruption: st.Interruption,
		Devices: st.Devices.Count(), Failures: st.Failures, Hours: st.Hours,
	}
	for _, n := range st.Hours {
		u.PeakHour = max(u.PeakHour, n)
	}
	return u
}

type statKey struct{ instance, day string }

// Limiter 执行限额并汇总计数，可以并发使用。
type Limiter struct {
	defaults map[string]int64
	store    *Store
	log      *slog.Logger

	mu      sync.Mutex
	day     string
	devices map[protocol.DeviceKey]int64
	stats   map[statKey]*Stats
}

// New 创建 Limiter，并载入今天已有的汇总，重启后实例的每日限额接着算。
func New(defaults map[string]int64, store *Store, log *slog.Logger, now time.Time) (*Limiter, error) {
	l := &Limiter{
		defaults: defaults,
		store:    store,
		log:      log,
		day:      dayOf(now),
		devices:  map[protocol.DeviceKey]int64{},
		stats:    map[statKey]*Stats{},
	}
	today, err := store.LoadDay(l.day)
	if err != nil {
		return nil, fmt.Errorf("读取今天的推送计数失败：%w", err)
	}
	for _, st := range today {
		l.stats[statKey{st.Instance, st.Day}] = st
	}
	return l, nil
}

// Admit 检查一条推送是否超出限额；没超出就计入（发给苹果之前计入，并发请求也超不过上限）。
// lim 是令牌里的限额表，没有的键用配置的默认值；负数表示不限。instance 为空（none 模式）
// 时不检查实例限额，只检查设备限额。
func (l *Limiter) Admit(instance string, lim map[string]int64, a Attempt, now time.Time) *Denial {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rollover(now)
	st := l.statsFor(instance)
	if limit, ok := l.limit(lim, "day"); ok && instance != "" && st.Count >= limit {
		return deny("day", limit, now, "这台实例今天的推送已达上限（%d 条）")
	}
	if limit, ok := l.limit(lim, "device_day"); ok && l.devices[a.Device] >= limit {
		return deny("device_day", limit, now, "这台设备今天收到的推送已达上限（%d 条）")
	}
	l.devices[a.Device]++
	st.Count++
	st.Hours[now.UTC().Hour()]++
	st.Type[a.Type]++
	st.Priority[strconv.Itoa(a.Priority)]++
	if a.Interruption != "" {
		st.Interruption[a.Interruption]++
	}
	st.Devices.Add(binary.BigEndian.Uint64(a.Device[:8]))
	st.dirty = true
	return nil
}

// Fail 记一次失败，reason 是结果码（rate_limited、unregistered、apns_error……）。
func (l *Limiter) Fail(instance, reason string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rollover(now)
	st := l.statsFor(instance)
	st.Failures[reason]++
	st.dirty = true
}

// Quota 返回实例的剩余额度；none 模式或不限额时返回 nil。
func (l *Limiter) Quota(instance string, lim map[string]int64, now time.Time) map[string]protocol.Quota {
	limit, ok := l.limit(lim, "day")
	if instance == "" || !ok {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rollover(now)
	used := l.statsFor(instance).Count
	return map[string]protocol.Quota{"day": {
		Limit: limit, Used: used, Remaining: max(0, limit-used), ResetAt: nextDay(now).Unix(),
	}}
}

// Usage 返回从 since（含）起的按天汇总，先把内存里的计数写盘。
func (l *Limiter) Usage(since string) ([]DayUsage, error) {
	if err := l.Flush(); err != nil {
		return nil, err
	}
	return l.store.Since(since)
}

// Flush 把有变化的汇总写进 SQLite，并从内存里去掉已经写完的旧日汇总。
func (l *Limiter) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var dirty []*Stats
	for _, st := range l.stats {
		if st.dirty {
			dirty = append(dirty, st)
		}
	}
	if len(dirty) > 0 {
		if err := l.store.Upsert(dirty); err != nil {
			return err
		}
	}
	for k, st := range l.stats {
		st.dirty = false
		if k.day != l.day {
			delete(l.stats, k)
		}
	}
	return nil
}

// Run 每 10 秒落盘一次、每小时清理过期数据，直到 ctx 结束。退出前调用方要再 Flush 一次。
func (l *Limiter) Run(ctx context.Context) {
	flush := time.NewTicker(10 * time.Second)
	prune := time.NewTicker(time.Hour)
	defer flush.Stop()
	defer prune.Stop()
	l.prune(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case <-flush.C:
			if err := l.Flush(); err != nil {
				l.log.Error("推送计数写盘失败", "error", err)
			}
		case now := <-prune.C:
			l.prune(now)
		}
	}
}

func (l *Limiter) prune(now time.Time) {
	before := now.UTC().AddDate(0, 0, -(RetentionDays - 1)).Format(dayLayout)
	if err := l.store.Prune(before); err != nil {
		l.log.Error("清理过期的推送计数失败", "error", err)
	}
}

// rollover 在跨过 UTC 零点时清空按设备的计数。调用方持有锁。
func (l *Limiter) rollover(now time.Time) {
	day := dayOf(now)
	if day == l.day {
		return
	}
	l.day = day
	clear(l.devices)
}

func (l *Limiter) statsFor(instance string) *Stats {
	k := statKey{instance, l.day}
	st := l.stats[k]
	if st == nil {
		st = newStats(instance, l.day)
		l.stats[k] = st
	}
	return st
}

func (l *Limiter) limit(lim map[string]int64, name string) (int64, bool) {
	v, ok := lim[name]
	if !ok {
		v, ok = l.defaults[name]
	}
	return v, ok && v >= 0
}

func deny(name string, limit int64, now time.Time, format string) *Denial {
	return &Denial{
		Limit:      name,
		Max:        limit,
		RetryAfter: nextDay(now).Sub(now),
		Message:    fmt.Sprintf(format, limit) + "，将在 UTC 零点（北京时间 8:00）恢复",
	}
}

func dayOf(t time.Time) string { return t.UTC().Format(dayLayout) }

func nextDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, time.UTC)
}
