// Package protocoltest 是推送中继协议的一致性测试：任何中继实现都应该能跑通 Run。
//
// 测试只通过 HTTP 和中继打交道，再到假的 APNs 上核对苹果实际收到了什么。被测中继要满足：
//   - 苹果的正式、测试接口都指向 NewAPNs 起的假 APNs，并信任它的证书（CertPEM）；
//   - 开放 alert 类型，不开放 voip；
//   - Target.Token 有 push 权限，当天的额度够发几十条；
//   - Target.LimitedToken（可以不给）是当天实例限额为 0 的凭证，用来核对 rate_limited 的格式。
//
// 限额怎么定、凭证怎么发、计数存在哪，是各个中继自己的事，这里只核对协议规定的行为。
package protocoltest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// APNs 是假的苹果推送服务（HTTP/2 + TLS）。它记录收到的推送，按设备令牌的前缀决定怎么回应：
// 410… 令牌已失效，400… 坏令牌，503… 苹果临时故障，其余都成功。
type APNs struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []Request
}

// Request 是假 APNs 收到的一条推送。
type Request struct {
	Path   string
	Header http.Header
	Body   []byte
}

// UnregisteredAt 是假 APNs 对 410… 令牌给出的失效时间（Unix 毫秒）。
const UnregisteredAt = 1767225600000

// NewAPNs 启动假 APNs，测试结束时自动关闭。
func NewAPNs(t testing.TB) *APNs {
	a := &APNs{}
	a.srv = httptest.NewUnstartedServer(http.HandlerFunc(a.serve))
	a.srv.EnableHTTP2 = true
	a.srv.StartTLS()
	t.Cleanup(a.srv.Close)
	return a
}

func (a *APNs) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	a.mu.Lock()
	a.reqs = append(a.reqs, Request{Path: r.URL.Path, Header: r.Header.Clone(), Body: body})
	a.mu.Unlock()
	token := strings.TrimPrefix(r.URL.Path, "/3/device/")
	w.Header().Set("apns-id", r.Header.Get("apns-id"))
	switch {
	case strings.HasPrefix(token, "410"):
		w.WriteHeader(http.StatusGone)
		fmt.Fprintf(w, `{"reason":"Unregistered","timestamp":%d}`, UnregisteredAt)
	case strings.HasPrefix(token, "400"):
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"reason":"BadDeviceToken"}`)
	case strings.HasPrefix(token, "503"):
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"reason":"ServiceUnavailable"}`)
	}
}

// URL 是假 APNs 的地址，苹果的正式、测试接口都配成它。
func (a *APNs) URL() string { return a.srv.URL }

// CertPEM 是假 APNs 的证书，中继要额外信任它。
func (a *APNs) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.srv.Certificate().Raw})
}

// Requests 返回到目前为止收到的推送。
func (a *APNs) Requests() []Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.reqs)
}

// Reset 清空记录。
func (a *APNs) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reqs = nil
}

// GenerateP8 生成一把 APNs 鉴权密钥（.p8 的 PEM），给被测中继用。
func GenerateP8(t testing.TB) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Target 是被测的中继。
type Target struct {
	// URL 是中继地址，比如 http://127.0.0.1:8080。
	URL string
	// Token 是有 push 权限、当天额度够用的凭证；none 模式的中继留空。
	Token string
	// LimitedURL、LimitedToken 是当天实例限额为 0 的调用方，用来核对 rate_limited 的格式。
	// 限额是全局配置的中继可以另起一个零额度的进程。LimitedURL 留空时用 URL，
	// LimitedToken 留空时跳过限额的用例。
	LimitedURL   string
	LimitedToken string
	// Topic 是中继允许推送的基础 Bundle ID。
	Topic string
	// APNs 是中继实际连接的假 APNs。
	APNs *APNs
}

// Run 按协议逐条核对被测中继。
func Run(t *testing.T, tg Target) {
	if tg.LimitedURL == "" {
		tg.LimitedURL = tg.URL
	}
	c := &client{t: t, tg: tg, http: &http.Client{Timeout: 30 * time.Second}}
	t.Run("info", c.info)
	t.Run("info 带凭证", c.infoWithCredential)
	t.Run("healthz", c.healthz)
	t.Run("鉴权", c.auth)
	t.Run("请求格式", c.requestErrors)
	t.Run("逐条检查", c.checks)
	t.Run("发给苹果", c.delivery)
	t.Run("苹果的回应", c.apnsResponses)
	if tg.LimitedToken != "" {
		t.Run("限额", c.rateLimited)
	}
}

type client struct {
	t    *testing.T
	tg   Target
	http *http.Client
}

func (c *client) do(t *testing.T, method, path, bearer string, body []byte) (int, map[string]any) {
	t.Helper()
	return c.doAt(t, c.tg.URL, method, path, bearer, body)
}

func (c *client) doAt(t *testing.T, base, method, path, bearer string, body []byte) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("%s %s：%v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("%s %s 的 Content-Type 应是 application/json，实际 %q", method, path, ct)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s %s 的响应不是 JSON 对象：%s", method, path, raw)
	}
	return resp.StatusCode, out
}

// push 发一批推送，返回状态码和响应。
func (c *client) push(t *testing.T, bearer string, messages ...map[string]any) (int, map[string]any) {
	t.Helper()
	return c.pushAt(t, c.tg.URL, bearer, messages...)
}

func (c *client) pushAt(t *testing.T, base, bearer string, messages ...map[string]any) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"messages": messages})
	return c.doAt(t, base, "POST", "/v1/push", bearer, body)
}

// results 发一批推送，要求整批 200，返回每条结果。
func (c *client) results(t *testing.T, bearer string, messages ...map[string]any) ([]map[string]any, map[string]any) {
	t.Helper()
	return c.resultsAt(t, c.tg.URL, bearer, messages...)
}

func (c *client) resultsAt(t *testing.T, base, bearer string, messages ...map[string]any) ([]map[string]any, map[string]any) {
	t.Helper()
	status, out := c.pushAt(t, base, bearer, messages...)
	if status != http.StatusOK {
		t.Fatalf("整批推送应返回 200，实际 %d：%v", status, out)
	}
	list, _ := out["results"].([]any)
	if len(list) != len(messages) {
		t.Fatalf("results 应和 messages 一一对应（%d 条），实际：%v", len(messages), out["results"])
	}
	res := make([]map[string]any, len(list))
	for i, r := range list {
		res[i], _ = r.(map[string]any)
		if res[i]["id"] != messages[i]["id"] {
			t.Errorf("第 %d 条结果的 id 应是 %v，实际 %v（结果顺序要和请求相同）", i, messages[i]["id"], res[i]["id"])
		}
	}
	return res, out
}

// newID 生成一个 UUID 形式的追踪 id。
func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// deviceToken 生成一个设备令牌，prefix 决定假 APNs 怎么回应。每条推送用不同的设备，
// 免得碰到中继按设备的每日上限。
func deviceToken(prefix string) string {
	b := make([]byte, 32)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)[len(prefix):]
}

// message 是一条合法的 alert 推送，extra 里的字段覆盖默认值（值为 nil 时删掉这个字段）。
func (c *client) message(token string, extra map[string]any) map[string]any {
	m := map[string]any{
		"id": newID(), "platform": "apns", "token": token, "topic": c.tg.Topic,
		"environment": "production", "type": "alert",
	}
	for k, v := range extra {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

func (c *client) info(t *testing.T) {
	status, info := c.do(t, "GET", "/v1/info", "", nil)
	if status != http.StatusOK {
		t.Fatalf("/v1/info 应返回 200，实际 %d：%v", status, info)
	}
	if info["protocol"] != float64(1) || info["max_batch"] != float64(100) || info["max_payload_bytes"] != float64(4096) {
		t.Errorf("protocol、max_batch、max_payload_bytes 应是 1、100、4096：%v", info)
	}
	if _, ok := info["aud"].(string); !ok {
		t.Errorf("aud 应是字符串：%v", info["aud"])
	}
	if s, _ := info["software"].(string); s == "" {
		t.Errorf("software 不能为空：%v", info["software"])
	}
	if !containsAll(info["platforms"], "apns") || !containsAll(info["environments"], "production", "development") {
		t.Errorf("platforms、environments 不对：%v %v", info["platforms"], info["environments"])
	}
	if !containsAll(info["topics"], c.tg.Topic) {
		t.Errorf("topics 里应有 %s：%v", c.tg.Topic, info["topics"])
	}
	types, _ := info["types"].(map[string]any)
	alert, _ := types["alert"].(map[string]any)
	if alert == nil || fmt.Sprint(alert["priorities"]) != "[10 5 1]" || alert["payload"] != "optional" || alert["aps"] == nil {
		t.Errorf("types.alert 不对：%v", types["alert"])
	}
	if _, ok := types["voip"]; ok {
		t.Error("types 里不应有 voip")
	}
	if auth, _ := info["auth"].(map[string]any); auth == nil || auth["mode"] == "" || auth["mode"] == nil {
		t.Errorf("auth.mode 不能为空：%v", info["auth"])
	}
	if _, ok := info["limits"].(map[string]any); !ok {
		t.Errorf("limits 应是对象：%v", info["limits"])
	}
	if _, ok := info["quota"]; ok {
		t.Errorf("不带凭证时不应有 quota：%v", info["quota"])
	}
}

// infoWithCredential 核对 /v1/info 带凭证时的行为：有效凭证多一个 quota；无效凭证照常返回、没有 quota。
func (c *client) infoWithCredential(t *testing.T) {
	if c.tg.Token == "" {
		t.Skip("none 模式不鉴权")
	}
	status, info := c.do(t, "GET", "/v1/info", "garbage", nil)
	if status != http.StatusOK || info["protocol"] != float64(1) {
		t.Fatalf("凭证无效时 /v1/info 仍应返回 200 和完整的信息，实际 %d：%v", status, info)
	}
	if _, ok := info["quota"]; ok {
		t.Errorf("凭证无效时不应有 quota：%v", info["quota"])
	}
	status, info = c.do(t, "GET", "/v1/info", c.tg.Token, nil)
	if status != http.StatusOK || info["protocol"] != float64(1) {
		t.Fatalf("带有效凭证时 /v1/info 应返回 200，实际 %d：%v", status, info)
	}
	if q, ok := info["quota"]; ok {
		checkQuota(t, q)
	}
	if c.tg.LimitedToken == "" {
		return
	}
	// 零额度的凭证一定有 quota：限额生效，就要能在 /v1/info 里看到
	status, info = c.doAt(t, c.tg.LimitedURL, "GET", "/v1/info", c.tg.LimitedToken, nil)
	q, _ := info["quota"].(map[string]any)
	day, _ := q["day"].(map[string]any)
	if status != http.StatusOK || day["limit"] != float64(0) || day["remaining"] != float64(0) {
		t.Errorf("零额度的凭证调 /v1/info 应带 quota.day（limit 0、remaining 0），实际 %d：%v", status, info["quota"])
	}
	checkQuota(t, info["quota"])
}

func (c *client) healthz(t *testing.T) {
	if status, out := c.do(t, "GET", "/healthz", "", nil); status != http.StatusOK || out["status"] != "ok" {
		t.Fatalf("/healthz 应返回 200 和 status: ok，实际 %d：%v", status, out)
	}
}

func (c *client) auth(t *testing.T) {
	if c.tg.Token == "" {
		t.Skip("none 模式不鉴权")
	}
	c.tg.APNs.Reset()
	for _, bearer := range []string{"", "garbage"} {
		status, out := c.push(t, bearer, c.message(deviceToken("a"), nil))
		if status != http.StatusUnauthorized || out["error"] != "unauthorized" || out["message"] == "" {
			t.Errorf("凭证 %q 应返回 401 unauthorized 和说明，实际 %d：%v", bearer, status, out)
		}
	}
	if n := len(c.tg.APNs.Requests()); n != 0 {
		t.Errorf("鉴权失败时不应发给苹果，实际发了 %d 条", n)
	}
}

func (c *client) requestErrors(t *testing.T) {
	c.tg.APNs.Reset()
	cases := []struct {
		name, body, code string
	}{
		{"不是 JSON", `not json`, "bad_request"},
		{"messages 为空", `{"messages": []}`, "bad_request"},
		{"超过 100 条", "", "too_many_messages"},
	}
	for _, tc := range cases {
		body := []byte(tc.body)
		if tc.body == "" {
			var many []map[string]any
			for range 101 {
				many = append(many, c.message(deviceToken("a"), nil))
			}
			body, _ = json.Marshal(map[string]any{"messages": many})
		}
		status, out := c.do(t, "POST", "/v1/push", c.tg.Token, body)
		if status != http.StatusBadRequest || out["error"] != tc.code || out["message"] == "" {
			t.Errorf("%s：应返回 400 %s 和说明，实际 %d：%v", tc.name, tc.code, status, out)
		}
	}
	if n := len(c.tg.APNs.Requests()); n != 0 {
		t.Errorf("整批被拒时不应发给苹果，实际发了 %d 条", n)
	}
}

// checks 核对第 5.3 节第 1–9 步：每条没通过检查的推送各自给出结果码和出问题的字段，都不发给苹果。
func (c *client) checks(t *testing.T) {
	c.tg.APNs.Reset()
	type check struct {
		name           string
		msg            map[string]any
		result, reason string
	}
	tok := func() string { return deviceToken("a") }
	cases := []check{
		{"id 不是 UUID", c.message(tok(), map[string]any{"id": "not-a-uuid"}), "invalid_message", "id"},
		{"不支持的平台", c.message(tok(), map[string]any{"platform": "fcm"}), "invalid_message", "platform"},
		{"设备令牌不是十六进制", c.message("not-hex", nil), "bad_token", "token"},
		{"Bundle ID 不在白名单", c.message(tok(), map[string]any{"topic": "com.example.not-allowed"}), "topic_not_allowed", "topic"},
		{"环境不对", c.message(tok(), map[string]any{"environment": "staging"}), "invalid_message", "environment"},
		{"expires_at 是负数", c.message(tok(), map[string]any{"expires_at": -1}), "invalid_message", "expires_at"},
		{"collapse_id 不是不透明值", c.message(tok(), map[string]any{"collapse_id": "订阅 42"}), "invalid_message", "collapse_id"},
		{"类型没开放", c.message(tok(), map[string]any{"type": "voip"}), "unsupported_type", "type"},
		{"优先级不允许", c.message(tok(), map[string]any{"priority": 7}), "invalid_message", "priority"},
		{"payload 不是密文", c.message(tok(), map[string]any{"payload": `{"title":"片名"}`}), "invalid_message", "payload"},
		{"aps 里有文字", c.message(tok(), map[string]any{"aps": map[string]any{"alert": map[string]any{"title": "流浪地球 已入库"}}}), "invalid_aps", "alert"},
		{"aps 里有 thread-id", c.message(tok(), map[string]any{"aps": map[string]any{"thread-id": "订阅-42"}}), "invalid_aps", "thread-id"},
		{"aps 字段是 null", c.message(tok(), map[string]any{"aps": map[string]any{"badge": nil}}), "invalid_aps", "badge"},
		{"角标是字符串", c.message(tok(), map[string]any{"aps": map[string]any{"badge": "3"}}), "invalid_aps", "badge"},
		{"最终 JSON 超过 4KB", c.message(tok(), map[string]any{"payload": "v1." + strings.Repeat("A", 4096)}), "payload_too_large", ""},
		{"字段类型不对", c.message(tok(), map[string]any{"priority": "high"}), "invalid_message", ""},
	}
	messages := make([]map[string]any, len(cases))
	for i, tc := range cases {
		messages[i] = tc.msg
	}
	res, _ := c.results(t, c.tg.Token, messages...)
	for i, tc := range cases {
		r := res[i]
		if r["result"] != tc.result || (tc.reason != "" && r["reason"] != tc.reason) {
			t.Errorf("%s：应是 %s（reason %q），实际 %v", tc.name, tc.result, tc.reason, r)
		}
		if m, _ := r["message"].(string); m == "" {
			t.Errorf("%s：结果应带给人看的 message：%v", tc.name, r)
		}
	}
	if n := len(c.tg.APNs.Requests()); n != 0 {
		t.Errorf("没通过检查的推送不应发给苹果，实际发了 %d 条", n)
	}
}

// delivery 核对第 8 节：发给苹果的请求头和内容，苹果只看得到通用文案和密文。
func (c *client) delivery(t *testing.T) {
	c.tg.APNs.Reset()
	const payload = "v1.k7Qm2xP9.bm9uY2Vub25jZQ.c2VjcmV0LWNpcGhlcnRleHQ"
	full := c.message(strings.ToUpper(deviceToken("a")), map[string]any{
		"priority": 10, "expires_at": 1767225600, "collapse_id": "k7Qm2xP9", "payload": payload,
		"aps":          map[string]any{"badge": 3, "interruption-level": "time-sensitive"},
		"future_field": map[string]any{"x": 1}, // 不认识的字段一律忽略
	})
	badgeOnly := c.message(deviceToken("a"), map[string]any{"aps": map[string]any{"badge": 0}})
	development := c.message(deviceToken("a"), map[string]any{"environment": "development"})
	res, out := c.results(t, c.tg.Token, full, badgeOnly, development)
	for i, r := range res {
		if r["result"] != "ok" {
			t.Errorf("第 %d 条应成功，实际 %v", i, r)
		}
	}
	if q, ok := out["quota"]; ok {
		checkQuota(t, q)
	}

	reqs := map[string]Request{}
	for _, r := range c.tg.APNs.Requests() {
		reqs[r.Header.Get("apns-id")] = r
	}
	if len(reqs) != 3 {
		t.Fatalf("苹果应收到 3 条推送，apns-id 等于实例的追踪 id，实际：%v", slices.Collect(maps.Keys(reqs)))
	}

	r := reqs[full["id"].(string)]
	h := r.Header
	if r.Path != "/3/device/"+strings.ToLower(full["token"].(string)) {
		t.Errorf("设备令牌应转成小写放在路径里：%s", r.Path)
	}
	want := map[string]string{
		"apns-topic": c.tg.Topic, "apns-push-type": "alert", "apns-priority": "10",
		"apns-expiration": "1767225600", "apns-collapse-id": "k7Qm2xP9",
	}
	for k, v := range want {
		if h.Get(k) != v {
			t.Errorf("请求头 %s 应是 %q，实际 %q", k, v, h.Get(k))
		}
	}
	checkProviderToken(t, h.Get("authorization"))
	var body map[string]any
	if err := json.Unmarshal(r.Body, &body); err != nil {
		t.Fatalf("发给苹果的不是 JSON：%s", r.Body)
	}
	aps, _ := body["aps"].(map[string]any)
	alert, _ := aps["alert"].(map[string]any)
	if body["e"] != payload || len(body) != 2 {
		t.Errorf("密文应原样放在顶层的 e，顶层只有 aps 和 e：%s", r.Body)
	}
	if title, _ := alert["title"].(string); title == "" || alert["body"] == "" || alert["body"] == nil || len(alert) != 2 {
		t.Errorf("带 payload 的 alert 应由中继填通用文案（只有 title、body）：%s", r.Body)
	}
	if aps["mutable-content"] != float64(1) || aps["badge"] != float64(3) || aps["interruption-level"] != "time-sensitive" {
		t.Errorf("aps 应带 mutable-content: 1 和实例填的控制字段：%s", r.Body)
	}

	r = reqs[badgeOnly["id"].(string)]
	if string(r.Body) != `{"aps":{"badge":0}}` {
		t.Errorf("不带 payload 的 alert 只转发控制字段，不加文案：%s", r.Body)
	}
	if r.Header.Get("apns-priority") != "10" || r.Header.Get("apns-expiration") != "" || r.Header.Get("apns-collapse-id") != "" {
		t.Errorf("没填的优先级用默认值 10，没填 expires_at、collapse_id 时不带对应的请求头：%v", r.Header)
	}
	if _, ok := reqs[development["id"].(string)]; !ok {
		t.Error("development 环境的推送也应发给苹果（测试环境）")
	}
}

// apnsResponses 核对苹果的各种回应对应的结果码。
func (c *client) apnsResponses(t *testing.T) {
	ok := c.message(deviceToken("a"), nil)
	gone := c.message(deviceToken("410"), nil)
	bad := c.message(deviceToken("400"), nil)
	down := c.message(deviceToken("503"), nil)
	res, _ := c.results(t, c.tg.Token, ok, gone, bad, down)
	if res[0]["result"] != "ok" {
		t.Errorf("200 应是 ok：%v", res[0])
	}
	if r := res[1]; r["result"] != "unregistered" || r["unregistered_at"] != float64(UnregisteredAt) || r["message"] == nil {
		t.Errorf("410 应是 unregistered，带 unregistered_at 和说明：%v", r)
	}
	if r := res[2]; r["result"] != "bad_token" || r["reason"] != "BadDeviceToken" || r["retryable"] != nil {
		t.Errorf("400 BadDeviceToken 应是 bad_token、不可重试：%v", r)
	}
	if r := res[3]; r["result"] != "apns_error" || r["reason"] != "ServiceUnavailable" || r["retryable"] != true {
		t.Errorf("503 应是 apns_error、可以重试：%v", r)
	}
}

// rateLimited 核对超出限额时的结果：不发给苹果，带限制名、恢复时间和说明。
func (c *client) rateLimited(t *testing.T) {
	c.tg.APNs.Reset()
	res, out := c.resultsAt(t, c.tg.LimitedURL, c.tg.LimitedToken, c.message(deviceToken("a"), nil), c.message(deviceToken("a"), nil))
	for i, r := range res {
		after, _ := r["retry_after"].(float64)
		if r["result"] != "rate_limited" || r["limit"] != "day" || r["reason"] != "day" || after <= 0 || after > 86400 || r["message"] == nil {
			t.Errorf("第 %d 条应是 rate_limited，带 limit、reason（day）、retry_after 和说明：%v", i, r)
		}
	}
	if n := len(c.tg.APNs.Requests()); n != 0 {
		t.Errorf("超出限额的推送不应发给苹果，实际发了 %d 条", n)
	}
	q, _ := out["quota"].(map[string]any)
	day, _ := q["day"].(map[string]any)
	if day["limit"] != float64(0) || day["remaining"] != float64(0) {
		t.Errorf("quota.day 应是 limit 0、remaining 0：%v", out["quota"])
	}
	checkQuota(t, out["quota"])
}

func checkQuota(t *testing.T, q any) {
	t.Helper()
	quota, ok := q.(map[string]any)
	if !ok {
		t.Errorf("quota 应是对象：%v", q)
		return
	}
	for name, v := range quota {
		item, _ := v.(map[string]any)
		limit, used, remaining, reset := item["limit"], item["used"], item["remaining"], item["reset_at"]
		if _, ok := limit.(float64); !ok {
			t.Errorf("quota.%s.limit 应是数字：%v", name, item)
		}
		if _, ok := used.(float64); !ok {
			t.Errorf("quota.%s.used 应是数字：%v", name, item)
		}
		if _, ok := remaining.(float64); !ok {
			t.Errorf("quota.%s.remaining 应是数字：%v", name, item)
		}
		if r, _ := reset.(float64); int64(r) <= time.Now().Unix() {
			t.Errorf("quota.%s.reset_at 应是将来的 Unix 秒：%v", name, item)
		}
	}
}

// checkProviderToken 核对发给苹果的 provider 令牌：ES256 签名的 JWT，头里有 kid，声明里有 iss（Team ID）和 iat。
func checkProviderToken(t *testing.T, header string) {
	t.Helper()
	raw, ok := strings.CutPrefix(header, "bearer ")
	if !ok {
		t.Errorf("authorization 应是 bearer <provider 令牌>：%q", header)
		return
	}
	claims := jwt.MapClaims{}
	tok, _, err := jwt.NewParser().ParseUnverified(raw, claims)
	if err != nil || tok.Method.Alg() != "ES256" || tok.Header["kid"] == nil || claims["iss"] == nil || claims["iat"] == nil {
		t.Errorf("provider 令牌应是带 kid、iss、iat 的 ES256 JWT：%v %v", err, header)
	}
}

func containsAll(list any, want ...string) bool {
	items, _ := list.([]any)
	for _, w := range want {
		if !slices.Contains(items, any(w)) {
			return false
		}
	}
	return true
}
