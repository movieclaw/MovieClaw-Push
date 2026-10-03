package limit

import (
	"crypto/sha256"
	"encoding/binary"
	"log/slog"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/movieclaw/movieclaw-push/protocol"
)

func newLimiter(t *testing.T, path string, now time.Time) (*Limiter, *Store) {
	t.Helper()
	store, err := OpenStore(path, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	l, err := New(map[string]int64{"day": 3, "device_day": 2}, store, slog.New(slog.DiscardHandler), now)
	if err != nil {
		t.Fatal(err)
	}
	return l, store
}

func device(s string) protocol.DeviceKey { return sha256.Sum256([]byte(s)) }

func TestDayAndDeviceLimits(t *testing.T) {
	now := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	l, _ := newLimiter(t, filepath.Join(t.TempDir(), "usage.db"), now)

	a := Attempt{Device: device("a"), Type: "alert", Priority: 10}
	if d := l.Admit("ins-1", nil, a, now); d != nil {
		t.Fatal(d)
	}
	if d := l.Admit("ins-1", nil, a, now); d != nil {
		t.Fatal(d)
	}
	// 同一台设备第三条：超出 device_day=2（跨实例也算）
	d := l.Admit("ins-2", nil, a, now)
	if d == nil || d.Limit != "device_day" {
		t.Fatalf("应触发 device_day：%+v", d)
	}
	if d.RetryAfter != 14*time.Hour {
		t.Fatalf("应在 UTC 零点恢复，实际 %v 后", d.RetryAfter)
	}
	// 换一台设备：实例第三条可以，第四条超出 day=3
	if d := l.Admit("ins-1", nil, Attempt{Device: device("b"), Type: "alert", Priority: 10}, now); d != nil {
		t.Fatal(d)
	}
	if d := l.Admit("ins-1", nil, Attempt{Device: device("c"), Type: "alert", Priority: 10}, now); d == nil || d.Limit != "day" {
		t.Fatalf("应触发 day：%+v", d)
	}
	// 令牌里的 lim 优先于默认值，负数表示不限
	if d := l.Admit("ins-1", map[string]int64{"day": -1}, Attempt{Device: device("c"), Type: "alert", Priority: 10}, now); d != nil {
		t.Fatalf("lim.day=-1 应不限：%+v", d)
	}
	// none 模式（实例为空）不检查实例限额
	for i := range 5 {
		if d := l.Admit("", nil, Attempt{Device: device(string(rune('d' + i))), Type: "alert", Priority: 10}, now); d != nil {
			t.Fatalf("none 模式不应受实例限额：%+v", d)
		}
	}

	q := l.Quota("ins-1", nil, now)["day"]
	if q.Limit != 3 || q.Used != 4 || q.Remaining != 0 {
		t.Fatalf("剩余额度不对：%+v", q)
	}
	if l.Quota("", nil, now) != nil {
		t.Fatal("none 模式没有实例额度")
	}

	// 过了 UTC 零点：设备计数清零，实例计数换新的一天
	tomorrow := now.Add(14 * time.Hour)
	if d := l.Admit("ins-1", nil, a, tomorrow); d != nil {
		t.Fatalf("新的一天应恢复：%+v", d)
	}
}

func TestUsagePersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	now := time.Date(2026, 10, 1, 10, 30, 0, 0, time.UTC)
	l, store := newLimiter(t, path, now)
	l.Admit("ins-1", nil, Attempt{Device: device("a"), Type: "alert", Priority: 10, Interruption: "time-sensitive"}, now)
	l.Admit("ins-1", nil, Attempt{Device: device("b"), Type: "background", Priority: 5}, now)
	l.Fail("ins-1", "unregistered", now)
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	store.Close()

	// 重启：今天的实例计数接着算，设备计数清零
	l2, _ := newLimiter(t, path, now)
	if d := l2.Admit("ins-1", nil, Attempt{Device: device("a"), Type: "alert", Priority: 10}, now); d != nil {
		t.Fatal(d)
	}
	if d := l2.Admit("ins-1", nil, Attempt{Device: device("c"), Type: "alert", Priority: 10}, now); d == nil || d.Limit != "day" {
		t.Fatalf("重启后实例限额应接着算：%+v", d)
	}
	days, err := l2.Usage("2026-09-25")
	if err != nil {
		t.Fatal(err)
	}
	if len(days) != 1 {
		t.Fatalf("应有一行汇总：%+v", days)
	}
	u := days[0]
	if u.Count != 3 || u.Type["alert"] != 2 || u.Type["background"] != 1 || u.Priority["10"] != 2 ||
		u.Interruption["time-sensitive"] != 1 || u.Failures["unregistered"] != 1 || u.Hours[10] != 3 || u.PeakHour != 3 {
		t.Fatalf("汇总不对：%+v", u)
	}
	if u.Devices != 2 { // a、b 两台；被拒的 c 不计
		t.Fatalf("不同设备数应约为 2，实际 %d", u.Devices)
	}
}

func TestPrune(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	old := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	l, store := newLimiter(t, path, old)
	l.Admit("ins-1", nil, Attempt{Device: device("a"), Type: "alert", Priority: 10}, old)
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	l.prune(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	days, err := store.Since("2026-01-01")
	if err != nil || len(days) != 0 {
		t.Fatalf("7 天前的计数应被清理：%+v %v", days, err)
	}
}

func TestHLLAccuracy(t *testing.T) {
	for _, n := range []int{0, 1, 5, 50, 1000, 20000} {
		var h HLL
		for i := range n {
			sum := sha256.Sum256(binary.BigEndian.AppendUint64(nil, uint64(i)))
			h.Add(binary.BigEndian.Uint64(sum[:8]))
			h.Add(binary.BigEndian.Uint64(sum[:8])) // 重复的不重复计数
		}
		// 近似计数：小基数时允许差 1（两台设备落进同一个寄存器），大基数时允许 10%
		got := float64(h.Count())
		if math.Abs(got-float64(n)) > max(1, 0.1*float64(n)) {
			t.Errorf("n=%d 估算为 %v，误差太大", n, got)
		}
	}
}
