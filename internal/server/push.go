package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/movieclaw/movieclaw-push/internal/apns"
	"github.com/movieclaw/movieclaw-push/internal/auth"
	"github.com/movieclaw/movieclaw-push/internal/limit"
	"github.com/movieclaw/movieclaw-push/internal/rules"
)

// Message 是实例发来的一条推送，格式见 docs/protocol.md「推送消息格式」（v1，定下后不再改）。
// 不认识的字段一律忽略，新版本实例发给老中继也不会出错。
type Message struct {
	ID          string                     `json:"id"`
	Platform    string                     `json:"platform"`
	Token       string                     `json:"token"`
	Topic       string                     `json:"topic"`
	Environment string                     `json:"environment"`
	Type        string                     `json:"type"`
	Priority    int                        `json:"priority"`
	ExpiresAt   *int64                     `json:"expires_at"`
	CollapseID  string                     `json:"collapse_id"`
	APS         map[string]json.RawMessage `json:"aps"`
	Payload     string                     `json:"payload"`
}

// Result 是一条推送的结果，和请求里的 messages 一一对应、顺序相同，并带回追踪 id。
type Result struct {
	ID     string `json:"id"`
	Result string `json:"result"`
	// Reason 是出问题的字段名、触发的限制名或苹果给的原因。
	Reason string `json:"reason,omitempty"`
	// Message 是给人看的中文说明。
	Message   string `json:"message,omitempty"`
	Retryable bool   `json:"retryable,omitempty"`
	// Limit、RetryAfter 只在 rate_limited 时出现。
	Limit      string `json:"limit,omitempty"`
	RetryAfter int64  `json:"retry_after,omitempty"`
	// UnregisteredAt 是苹果给的令牌失效时间（Unix 毫秒），只在 unregistered 时出现。
	UnregisteredAt int64 `json:"unregistered_at,omitempty"`
}

// 结果码。invalid_aps、invalid_message、payload_too_large 定义在 rules 包。
const (
	resultOK              = "ok"
	resultUnregistered    = "unregistered"
	resultBadToken        = "bad_token"
	resultRateLimited     = "rate_limited"
	resultUnsupportedType = "unsupported_type"
	resultTopicNotAllowed = "topic_not_allowed"
	resultAPNsError       = "apns_error"
)

var (
	uuidRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	tokenRe    = regexp.MustCompile(`^[0-9a-fA-F]{32,400}$`)
	collapseRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// concurrency 是一个批次里同时发给苹果的条数，它们共用一条 HTTP/2 连接的多个流。
const concurrency = 8

func (s *Server) push(w http.ResponseWriter, r *http.Request) {
	p, err := s.opts.Auth.Authenticate(r.Context(), bearer(r))
	if err != nil {
		var ae *auth.Error
		if errors.As(err, &ae) {
			writeError(w, ae.Status, ae.Code, ae.Message)
		} else {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
		}
		return
	}
	var req struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法的 JSON："+err.Error())
		return
	}
	if len(req.Messages) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "messages 不能为空")
		return
	}
	if len(req.Messages) > MaxBatch {
		writeError(w, http.StatusBadRequest, "too_many_messages", fmt.Sprintf("一次最多 %d 条推送", MaxBatch))
		return
	}

	results := make([]Result, len(req.Messages))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, raw := range req.Messages {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			results[i] = s.deliver(r.Context(), p, raw)
		})
	}
	wg.Wait()

	resp := map[string]any{"results": results}
	// 带上剩余额度，实例快到上限时可以主动取舍：优先发 alert，静默推送和实时活动可以丢
	if q := s.opts.Limiter.Quota(p.Instance, p.Limits, s.now()); q != nil {
		resp["quota"] = q
	}
	writeJSON(w, http.StatusOK, resp)
}

// deliver 处理一条推送：格式检查 → 白名单 → 类型规则 → 限额 → 发给苹果。
func (s *Server) deliver(ctx context.Context, p *auth.Principal, raw json.RawMessage) Result {
	now := s.now()
	var m Message
	if err := json.Unmarshal(raw, &m); err != nil {
		var probe struct {
			ID any `json:"id"`
		}
		_ = json.Unmarshal(raw, &probe)
		m.ID, _ = probe.ID.(string)
		return s.finish(ctx, p, m.ID, limit.DeviceKey{}, Result{ID: m.ID,
			Result: rules.ResultInvalidMessage, Message: "推送格式错误：" + err.Error()}, now)
	}
	var dev limit.DeviceKey
	reject := func(result, reason, msg string) Result {
		return s.finish(ctx, p, m.ID, dev, Result{ID: m.ID, Result: result, Reason: reason, Message: msg}, now)
	}

	switch {
	case !uuidRe.MatchString(m.ID):
		return reject(rules.ResultInvalidMessage, "id", "id 必须是实例生成的随机 UUID")
	case m.Platform != "apns":
		return reject(rules.ResultInvalidMessage, "platform", fmt.Sprintf("这个中继不支持 %q 平台", m.Platform))
	case !tokenRe.MatchString(m.Token):
		return reject(resultBadToken, "token", "设备令牌格式不对，应是十六进制字符串")
	}
	token := strings.ToLower(m.Token)
	dev = sha256.Sum256([]byte(token))

	switch {
	case !s.topicAllowed(m.Topic):
		return reject(resultTopicNotAllowed, "topic", fmt.Sprintf("这个中继不能推送 %s 的 App，请改用自建中继", m.Topic))
	case m.Environment != "production" && m.Environment != "development":
		return reject(rules.ResultInvalidMessage, "environment", "environment 只能是 production 或 development")
	case m.ExpiresAt != nil && *m.ExpiresAt < 0:
		return reject(rules.ResultInvalidMessage, "expires_at", "expires_at 不能是负数")
	case m.CollapseID != "" && !collapseRe.MatchString(m.CollapseID):
		return reject(rules.ResultInvalidMessage, "collapse_id", "collapse_id 只能是不超过 64 个字符的不透明值（字母、数字、_、-）")
	}
	rule, ok := s.opts.Rules.Lookup(m.Type)
	if !ok {
		return reject(resultUnsupportedType, "type", fmt.Sprintf("这个中继没有开放 %q 类型的推送", m.Type))
	}
	out, rerr := s.opts.Rules.Build(rule, rules.Input{Priority: m.Priority, APS: m.APS, Payload: m.Payload})
	if rerr != nil {
		return reject(rerr.Result, rerr.Reason, rerr.Message)
	}

	attempt := limit.Attempt{Device: dev, Type: m.Type, Priority: out.Priority, Interruption: out.Interruption}
	if d := s.opts.Limiter.Admit(p.Instance, p.Limits, attempt, now); d != nil {
		return s.finish(ctx, p, m.ID, dev, Result{
			ID: m.ID, Result: resultRateLimited, Reason: d.Limit, Message: d.Message,
			Limit: d.Limit, RetryAfter: int64(math.Ceil(d.RetryAfter.Seconds())),
		}, now)
	}

	resp, err := s.opts.Sender.Push(ctx, &apns.Notification{
		ID:          m.ID,
		Token:       token,
		Topic:       m.Topic + out.TopicSuffix,
		PushType:    out.PushType,
		Priority:    out.Priority,
		Expiration:  m.ExpiresAt,
		CollapseID:  m.CollapseID,
		Development: m.Environment == "development",
		Body:        out.Body,
	})
	return s.finish(ctx, p, m.ID, dev, mapResponse(Result{ID: m.ID}, resp, err), now)
}

// mapResponse 把苹果的回应翻译成结果码。
func mapResponse(res Result, resp *apns.Response, err error) Result {
	if err != nil {
		res.Result, res.Reason, res.Retryable = resultAPNsError, "network", true
		res.Message = "连接苹果推送服务失败：" + err.Error()
		return res
	}
	res.Reason = resp.Reason
	switch {
	case resp.StatusCode == http.StatusOK:
		res.Result = resultOK
	case resp.StatusCode == http.StatusGone:
		res.Result = resultUnregistered
		res.UnregisteredAt = resp.Timestamp
		res.Message = "设备令牌已失效（App 被卸载或关闭了通知），请删除这台设备的推送令牌"
	case resp.StatusCode == http.StatusBadRequest && resp.Reason == "BadDeviceToken":
		res.Result = resultBadToken
		res.Message = "苹果不认这个设备令牌，可能只是令牌和环境（production/development）不匹配"
	case resp.StatusCode == http.StatusRequestEntityTooLarge:
		res.Result = rules.ResultTooLarge
		res.Message = "苹果认为推送内容太大"
	default:
		res.Result = resultAPNsError
		// 429 是苹果对单台设备限频；5xx 是苹果的临时故障；403 是中继自己的密钥配置问题，修好后能恢复
		res.Retryable = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 ||
			resp.StatusCode == http.StatusForbidden
		res.Message = fmt.Sprintf("苹果返回 %d %s", resp.StatusCode, resp.Reason)
	}
	return res
}

// finish 记失败计数和日志。日志只记实例、追踪 id、令牌哈希前缀和结果，不记内容和完整令牌。
func (s *Server) finish(ctx context.Context, p *auth.Principal, id string, dev limit.DeviceKey, res Result, now time.Time) Result {
	if res.Result != resultOK {
		s.opts.Limiter.Fail(p.Instance, res.Result, now)
	}
	attrs := []any{"instance", p.Instance, "id", id, "result", res.Result}
	if dev != (limit.DeviceKey{}) {
		attrs = append(attrs, "token", hex.EncodeToString(dev[:4]))
	}
	if res.Reason != "" {
		attrs = append(attrs, "reason", res.Reason)
	}
	level := slog.LevelInfo
	if res.Result == resultAPNsError {
		level = slog.LevelWarn
	}
	s.opts.Log.Log(ctx, level, "推送", attrs...)
	return res
}
