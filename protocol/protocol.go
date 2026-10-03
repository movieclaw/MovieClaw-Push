// Package protocol 是推送中继协议（docs/protocol.md）里可以直接执行的部分：消息和响应的
// 格式、逐条检查的顺序、推送类型规则和 aps 允许清单、最终发给苹果的内容、苹果的回应对应
// 的结果码。
//
// 中继的实现各自负责鉴权、限额、计数和配置，协议本身只调用这里的函数，不在这里放任何
// 策略。这样不同的中继实现对同一条推送给出同样的结果，「中继只看得到密文」的承诺也只在
// 这一处执行。protocoltest 包是配套的一致性测试。
package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/movieclaw/movieclaw-push/apns"
)

// Version 是推送中继协议的版本。只有破坏兼容时才升；加类型、加字段、加限额都不算。
const Version = 1

// MaxBatch 是一次请求最多带的推送条数。
const MaxBatch = 100

// MaxBodyBytes 是 POST /v1/push 请求体的上限。
const MaxBodyBytes = 1 << 20

// MaxPayloadBytes 是最终发给苹果的 JSON 的上限（APNs 对普通推送的限制）。
const MaxPayloadBytes = 4096

// 单条推送的结果码，见 docs/protocol.md「结果码」。
const (
	ResultOK              = "ok"
	ResultUnregistered    = "unregistered"
	ResultBadToken        = "bad_token"
	ResultRateLimited     = "rate_limited"
	ResultUnsupportedType = "unsupported_type"
	ResultTopicNotAllowed = "topic_not_allowed"
	ResultTooLarge        = "payload_too_large"
	ResultInvalidAPS      = "invalid_aps"
	ResultInvalidMessage  = "invalid_message"
	ResultAPNsError       = "apns_error"
)

// 整个请求出错时的错误码，见 docs/protocol.md「接口一览」。
const (
	ErrBadRequest      = "bad_request"
	ErrTooManyMessages = "too_many_messages"
	ErrUnauthorized    = "unauthorized"
	ErrForbidden       = "forbidden"
	ErrInternal        = "internal"
	// ErrUnavailable 是中继暂时没法核实凭证（比如它依赖的服务连不上），实例稍后重试即可。
	ErrUnavailable = "unavailable"
)

// Message 是实例发来的一条推送，格式见 docs/protocol.md「推送消息」（v1，定下后不再改）。
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

// Quota 是一个限制的剩余额度。
type Quota struct {
	Limit     int64 `json:"limit"`
	Used      int64 `json:"used"`
	Remaining int64 `json:"remaining"`
	ResetAt   int64 `json:"reset_at"`
}

// Response 是 POST /v1/push 的响应。Quota 是调用方的剩余额度，不限额时没有。
type Response struct {
	Results []Result         `json:"results"`
	Quota   map[string]Quota `json:"quota,omitempty"`
}

// Info 是 GET /v1/info 的响应。
type Info struct {
	Protocol        int              `json:"protocol"`
	Software        string           `json:"software"`
	Aud             string           `json:"aud"`
	Platforms       []string         `json:"platforms"`
	Environments    []string         `json:"environments"`
	Topics          []string         `json:"topics"`
	Types           map[string]any   `json:"types"`
	Auth            map[string]any   `json:"auth"`
	Limits          map[string]int64 `json:"limits"`
	MaxBatch        int              `json:"max_batch"`
	MaxPayloadBytes int              `json:"max_payload_bytes"`
	// Quota 是调用方的剩余额度，只在请求带了有效凭证、而且有限额时才有。
	Quota map[string]Quota `json:"quota,omitempty"`
}

// DeviceKey 是设备令牌（小写）的 SHA-256。中继只在内存里用它按设备计数，日志只记前 4 字节。
type DeviceKey [32]byte

var (
	uuidRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	tokenRe    = regexp.MustCompile(`^[0-9a-fA-F]{32,400}$`)
	collapseRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Checker 按协议检查推送：能推送的 Bundle ID 白名单加上推送类型规则表。可以并发使用。
type Checker struct {
	topics []string
	table  *Table
}

// NewChecker 创建检查器。topics 是能推送的基础 Bundle ID。
func NewChecker(topics []string, table *Table) *Checker {
	return &Checker{topics: topics, table: table}
}

// Info 拼出 /v1/info 的响应。auth 是鉴权方式（至少有 mode），limits 是默认限额。
func (c *Checker) Info(software, aud string, auth map[string]any, limits map[string]int64) Info {
	return Info{
		Protocol:        Version,
		Software:        software,
		Aud:             aud,
		Platforms:       []string{"apns"},
		Environments:    []string{"production", "development"},
		Topics:          c.topics,
		Types:           c.table.Describe(),
		Auth:            auth,
		Limits:          limits,
		MaxBatch:        MaxBatch,
		MaxPayloadBytes: MaxPayloadBytes,
	}
}

// Prepared 是一条推送的检查结果。检查没通过时 Notification 为 nil，ID、Device 能解析出来就有值。
type Prepared struct {
	ID     string
	Device DeviceKey
	// Type、Priority、Interruption 给限额和计数用，检查通过时才有值。
	Type         string
	Priority     int
	Interruption string
	Notification *apns.Notification
}

// Prepare 按 docs/protocol.md「中继的处理顺序」第 1–9 步检查一条推送，拼出要发给苹果的内容。
// 没通过时返回的 *Result 就是这条推送的结果。限额（第 10 步）由中继自己检查。
func (c *Checker) Prepare(raw json.RawMessage) (Prepared, *Result) {
	var p Prepared
	var m Message
	if err := json.Unmarshal(raw, &m); err != nil {
		var probe struct {
			ID any `json:"id"`
		}
		_ = json.Unmarshal(raw, &probe)
		p.ID, _ = probe.ID.(string)
		return p, &Result{ID: p.ID, Result: ResultInvalidMessage, Message: "推送格式错误：" + err.Error()}
	}
	p.ID = m.ID
	reject := func(result, reason, msg string) (Prepared, *Result) {
		return p, &Result{ID: m.ID, Result: result, Reason: reason, Message: msg}
	}

	switch {
	case !uuidRe.MatchString(m.ID):
		return reject(ResultInvalidMessage, "id", "id 必须是实例生成的随机 UUID")
	case m.Platform != "apns":
		return reject(ResultInvalidMessage, "platform", fmt.Sprintf("这个中继不支持 %q 平台", m.Platform))
	case !tokenRe.MatchString(m.Token):
		return reject(ResultBadToken, "token", "设备令牌格式不对，应是十六进制字符串")
	}
	token := strings.ToLower(m.Token)
	p.Device = sha256.Sum256([]byte(token))

	switch {
	case !slices.Contains(c.topics, m.Topic):
		return reject(ResultTopicNotAllowed, "topic", fmt.Sprintf("这个中继不能推送 %s 的 App，请改用自建中继", m.Topic))
	case m.Environment != "production" && m.Environment != "development":
		return reject(ResultInvalidMessage, "environment", "environment 只能是 production 或 development")
	case m.ExpiresAt != nil && *m.ExpiresAt < 0:
		return reject(ResultInvalidMessage, "expires_at", "expires_at 不能是负数")
	case m.CollapseID != "" && !collapseRe.MatchString(m.CollapseID):
		return reject(ResultInvalidMessage, "collapse_id", "collapse_id 只能是不超过 64 个字符的不透明值（字母、数字、_、-）")
	}
	rule, ok := c.table.lookup(m.Type)
	if !ok {
		return reject(ResultUnsupportedType, "type", fmt.Sprintf("这个中继没有开放 %q 类型的推送", m.Type))
	}
	out, rerr := c.table.build(rule, input{Priority: m.Priority, APS: m.APS, Payload: m.Payload})
	if rerr != nil {
		return reject(rerr.Result, rerr.Reason, rerr.Message)
	}

	p.Type, p.Priority, p.Interruption = m.Type, out.Priority, out.Interruption
	p.Notification = &apns.Notification{
		ID:          m.ID,
		Token:       token,
		Topic:       m.Topic + out.TopicSuffix,
		PushType:    out.PushType,
		Priority:    out.Priority,
		Expiration:  m.ExpiresAt,
		CollapseID:  m.CollapseID,
		Development: m.Environment == "development",
		Body:        out.Body,
	}
	return p, nil
}

// Outcome 把苹果对一条推送的回应翻译成结果。err 是连不上苹果之类的网络错误。
func Outcome(id string, resp *apns.Response, err error) Result {
	res := Result{ID: id}
	if err != nil {
		res.Result, res.Reason, res.Retryable = ResultAPNsError, "network", true
		res.Message = "连接苹果推送服务失败：" + err.Error()
		return res
	}
	res.Reason = resp.Reason
	switch {
	case resp.StatusCode == http.StatusOK:
		res.Result = ResultOK
	case resp.StatusCode == http.StatusGone:
		res.Result = ResultUnregistered
		res.UnregisteredAt = resp.Timestamp
		res.Message = "设备令牌已失效（App 被卸载或关闭了通知），请删除这台设备的推送令牌"
	case resp.StatusCode == http.StatusBadRequest && resp.Reason == "BadDeviceToken":
		res.Result = ResultBadToken
		res.Message = "苹果不认这个设备令牌，可能只是令牌和环境（production/development）不匹配"
	case resp.StatusCode == http.StatusRequestEntityTooLarge:
		res.Result = ResultTooLarge
		res.Message = "苹果认为推送内容太大"
	default:
		res.Result = ResultAPNsError
		// 429 是苹果对单台设备限频；5xx 是苹果的临时故障；403 是中继自己的密钥配置问题，修好后能恢复
		res.Retryable = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 ||
			resp.StatusCode == http.StatusForbidden
		res.Message = fmt.Sprintf("苹果返回 %d %s", resp.StatusCode, resp.Reason)
	}
	return res
}

// RateLimited 是超出限额的结果。limit 是触发的限制名（day、device_day……），message 是给人看的
// 中文说明：实例原样显示，新的限制类型老实例也能看懂。
func RateLimited(id, limit string, retryAfter time.Duration, message string) Result {
	return Result{
		ID: id, Result: ResultRateLimited, Reason: limit, Message: message,
		Limit: limit, RetryAfter: int64((retryAfter + time.Second - 1) / time.Second),
	}
}

// LogAttrs 是记录一条推送结果时允许写进日志的字段：追踪 id、结果、原因和设备令牌哈希的前缀。
// 推送内容和完整令牌不进日志（docs/protocol.md「日志」）。中继自己再加上调用方的标识。
func (p Prepared) LogAttrs(res Result) []any {
	attrs := []any{"id", p.ID, "result", res.Result}
	if p.Device != (DeviceKey{}) {
		attrs = append(attrs, "token", hex.EncodeToString(p.Device[:4]))
	}
	if res.Reason != "" {
		attrs = append(attrs, "reason", res.Reason)
	}
	return attrs
}

// RequestError 是整个请求出错：HTTP 状态码、错误码和给人看的说明。
type RequestError struct {
	Status  int
	Code    string
	Message string
}

func (e *RequestError) Error() string { return e.Message }

// ReadBatch 读出 POST /v1/push 请求体里的 messages（1MB、1–100 条以内）。
func ReadBatch(w http.ResponseWriter, r *http.Request) ([]json.RawMessage, *RequestError) {
	var req struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes)).Decode(&req); err != nil {
		return nil, &RequestError{http.StatusBadRequest, ErrBadRequest, "请求体不是合法的 JSON：" + err.Error()}
	}
	if len(req.Messages) == 0 {
		return nil, &RequestError{http.StatusBadRequest, ErrBadRequest, "messages 不能为空"}
	}
	if len(req.Messages) > MaxBatch {
		return nil, &RequestError{http.StatusBadRequest, ErrTooManyMessages, fmt.Sprintf("一次最多 %d 条推送", MaxBatch)}
	}
	return req.Messages, nil
}

// Bearer 取出 Authorization: Bearer 后面的凭证，没有时返回空串。
func Bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// WriteJSON 写一个 JSON 响应。
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError 写整个请求级别的错误：{"error": "<错误码>", "message": "<中文说明>"}。
// err 不是 *RequestError 时按 500 处理。
func WriteError(w http.ResponseWriter, err error) {
	var re *RequestError
	if !errors.As(err, &re) {
		re = &RequestError{http.StatusInternalServerError, ErrInternal, err.Error()}
	}
	WriteJSON(w, re.Status, map[string]string{"error": re.Code, "message": re.Message})
}
