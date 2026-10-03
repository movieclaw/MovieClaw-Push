package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/movieclaw/movieclaw-push/apns"
	"github.com/movieclaw/movieclaw-push/internal/auth"
	"github.com/movieclaw/movieclaw-push/internal/limit"
	"github.com/movieclaw/movieclaw-push/protocol"
)

type fakeAuth struct{}

func (fakeAuth) Mode() string         { return "static" }
func (fakeAuth) Info() map[string]any { return map[string]any{"mode": "static"} }
func (fakeAuth) Authenticate(_ context.Context, b string) (*auth.Principal, error) {
	switch b {
	case "good":
		return &auth.Principal{Instance: "ins-1"}, nil
	case "no-scope":
		return nil, &protocol.RequestError{Status: http.StatusForbidden, Code: "forbidden", Message: "实例凭证没有 push 权限"}
	}
	return nil, &protocol.RequestError{Status: http.StatusUnauthorized, Code: "unauthorized", Message: "实例凭证无效或已过期"}
}

// fakeSender 按设备令牌决定苹果怎么回应。
type fakeSender struct {
	mu   sync.Mutex
	sent []*apns.Notification
}

func (f *fakeSender) Push(_ context.Context, n *apns.Notification) (*apns.Response, error) {
	f.mu.Lock()
	f.sent = append(f.sent, n)
	f.mu.Unlock()
	switch {
	case strings.HasPrefix(n.Token, "410"):
		return &apns.Response{StatusCode: 410, Reason: "Unregistered", Timestamp: 1767225600000}, nil
	case strings.HasPrefix(n.Token, "400"):
		return &apns.Response{StatusCode: 400, Reason: "BadDeviceToken"}, nil
	case strings.HasPrefix(n.Token, "503"):
		return &apns.Response{StatusCode: 503, Reason: "ServiceUnavailable"}, nil
	case strings.HasPrefix(n.Token, "eee"):
		return nil, errors.New("connection reset")
	}
	return &apns.Response{StatusCode: 200, APNsID: n.ID}, nil
}

type harness struct {
	srv    *Server
	h      http.Handler
	sender *fakeSender
	logs   *bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWithLimits(t, map[string]int64{"day": 5000, "device_day": 500})
}

func newHarnessWithLimits(t *testing.T, defaults map[string]int64) *harness {
	t.Helper()
	table, err := protocol.NewTable(nil, []string{"alert", "background"}, protocol.Options{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := limit.OpenStore(filepath.Join(t.TempDir(), "usage.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(&lockedWriter{w: logs}, nil))
	limiter, err := limit.New(defaults, store, log, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sender := &fakeSender{}
	s := New(Options{
		Aud: "https://push.example.com", Checker: protocol.NewChecker([]string{"io.movieclaw.app"}, table), Auth: fakeAuth{},
		Limiter: limiter, Sender: sender, Defaults: defaults, Version: "test", Log: log,
	})
	return &harness{srv: s, h: s.Handler(), sender: sender, logs: logs}
}

type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (h *harness) do(t *testing.T, method, path, bearer, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应不是 JSON：%s", rec.Body)
	}
	return rec.Code, out
}

const token = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

func msg(id, tok string, extra string) string {
	return fmt.Sprintf(`{"id":"%s","platform":"apns","token":"%s","topic":"io.movieclaw.app","environment":"production","type":"alert"%s}`, id, tok, extra)
}

func uuid(i int) string { return fmt.Sprintf("6f1c2a9e-3b7d-4c55-9a10-%012d", i) }

func TestInfo(t *testing.T) {
	h := newHarness(t)
	code, out := h.do(t, "GET", "/v1/info", "", "")
	if code != 200 || out["protocol"].(float64) != 1 || out["aud"] != "https://push.example.com" {
		t.Fatalf("info 不对：%d %v", code, out)
	}
	types := out["types"].(map[string]any)
	if _, ok := types["alert"]; !ok || len(types) != 2 {
		t.Fatalf("开放的类型不对：%v", types)
	}
	if out["auth"].(map[string]any)["mode"] != "static" {
		t.Fatalf("鉴权方式不对：%v", out["auth"])
	}
}

func TestPushRequiresCredential(t *testing.T) {
	h := newHarness(t)
	body := `{"messages":[` + msg(uuid(1), token, "") + `]}`
	if code, out := h.do(t, "POST", "/v1/push", "", body); code != 401 || out["error"] != "unauthorized" {
		t.Fatalf("没有凭证应返回 401：%d %v", code, out)
	}
	if code, _ := h.do(t, "POST", "/v1/push", "no-scope", body); code != 403 {
		t.Fatalf("缺少权限应返回 403：%d", code)
	}
	if len(h.sender.sent) != 0 {
		t.Fatal("鉴权失败时不应推送")
	}
}

func TestBatchResults(t *testing.T) {
	h := newHarness(t)
	payload := "v1.k7Qm2xP9.bm9uY2U.Y2lwaGVydGV4dA"
	messages := []string{
		msg(uuid(1), token, `,"payload":"`+payload+`","aps":{"badge":3},"future_field":{"x":1}`),
		msg(uuid(2), token, `,"aps":{"alert":{"title":"流浪地球 已入库"}}`),
		strings.Replace(msg(uuid(3), token, ""), `"type":"alert"`, `"type":"liveactivity"`, 1),
		strings.Replace(msg(uuid(4), token, ""), "io.movieclaw.app", "com.example.other", 1),
		msg(uuid(5), token, `,"priority":"high"`),
		msg(uuid(6), "410"+token[3:], ""),
		msg(uuid(7), "400"+token[3:], ""),
		msg(uuid(8), "eee"+token[3:], ""),
		msg(uuid(9), "not-hex", ""),
		msg("not-a-uuid", token, ""),
		msg(uuid(11), "503"+token[3:], ""),
	}
	code, out := h.do(t, "POST", "/v1/push", "good", `{"messages":[`+strings.Join(messages, ",")+`]}`)
	if code != 200 {
		t.Fatalf("整批应返回 200：%d %v", code, out)
	}
	results := out["results"].([]any)
	want := []struct{ id, result, reason string }{
		{uuid(1), "ok", ""},
		{uuid(2), "invalid_aps", "alert"},
		{uuid(3), "unsupported_type", "type"},
		{uuid(4), "topic_not_allowed", "topic"},
		{uuid(5), "invalid_message", ""},
		{uuid(6), "unregistered", "Unregistered"},
		{uuid(7), "bad_token", "BadDeviceToken"},
		{uuid(8), "apns_error", "network"},
		{uuid(9), "bad_token", "token"},
		{"not-a-uuid", "invalid_message", "id"},
		{uuid(11), "apns_error", "ServiceUnavailable"},
	}
	if len(results) != len(want) {
		t.Fatalf("结果条数不对：%v", results)
	}
	for i, w := range want {
		r := results[i].(map[string]any)
		if r["id"] != w.id || r["result"] != w.result || (w.reason != "" && r["reason"] != w.reason) {
			t.Errorf("第 %d 条：期望 %+v，实际 %v", i, w, r)
		}
	}
	if r := results[7].(map[string]any); r["retryable"] != true {
		t.Errorf("网络错误应可重试：%v", r)
	}
	if r := results[6].(map[string]any); r["retryable"] != nil {
		t.Errorf("bad_token 不应可重试：%v", r)
	}

	// 第一条按规则转换后交给苹果：通用文案 + 密文，追踪 id 原样作为 apns-id
	var first *apns.Notification
	for _, n := range h.sender.sent {
		if n.ID == uuid(1) {
			first = n
		}
	}
	if first == nil || first.Topic != "io.movieclaw.app" || first.PushType != "alert" || first.Priority != 10 ||
		!strings.Contains(string(first.Body), `"e":"`+payload+`"`) || !strings.Contains(string(first.Body), `"mutable-content":1`) {
		t.Fatalf("交给苹果的推送不对：%+v %s", first, first.Body)
	}

	// 日志里查不到推送内容和完整的设备令牌
	logs := h.logs.String()
	if strings.Contains(logs, token) || strings.Contains(logs, payload) || strings.Contains(logs, "流浪地球") {
		t.Fatalf("日志泄露了令牌或内容：\n%s", logs)
	}
	if !strings.Contains(logs, uuid(1)) || !strings.Contains(logs, `"token":"`) {
		t.Fatal("日志应记追踪 id 和令牌哈希前缀")
	}
}

func TestRateLimit(t *testing.T) {
	h := newHarnessWithLimits(t, map[string]int64{"day": 4, "device_day": 500})
	var messages []string
	for i := range 6 {
		messages = append(messages, msg(uuid(i), token, ""))
	}
	_, out := h.do(t, "POST", "/v1/push", "good", `{"messages":[`+strings.Join(messages, ",")+`]}`)
	results := out["results"].([]any)
	limited := 0
	for _, r := range results {
		r := r.(map[string]any)
		if r["result"] == "rate_limited" {
			limited++
			if r["limit"] != "day" || r["retry_after"].(float64) <= 0 || !strings.Contains(r["message"].(string), "上限") {
				t.Fatalf("rate_limited 应带限制名、retry_after 和中文说明：%v", r)
			}
		}
	}
	if limited != 2 {
		t.Fatalf("limits.day=4，6 条里应有 2 条被限：%d", limited)
	}
	q := out["quota"].(map[string]any)["day"].(map[string]any)
	if q["limit"].(float64) != 4 || q["remaining"].(float64) != 0 {
		t.Fatalf("剩余额度不对：%v", q)
	}
}

func TestBatchSize(t *testing.T) {
	h := newHarness(t)
	var messages []string
	for i := range protocol.MaxBatch + 1 {
		messages = append(messages, msg(uuid(i), token, ""))
	}
	if code, out := h.do(t, "POST", "/v1/push", "good", `{"messages":[`+strings.Join(messages, ",")+`]}`); code != 400 || out["error"] != "too_many_messages" {
		t.Fatalf("超过 100 条应返回 400：%d %v", code, out)
	}
	if code, _ := h.do(t, "POST", "/v1/push", "good", `not json`); code != 400 {
		t.Fatalf("坏 JSON 应返回 400：%d", code)
	}
}
