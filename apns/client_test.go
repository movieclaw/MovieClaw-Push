package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeAPNs 是一个 HTTP/2 的假苹果，记录收到的请求，按 provider 令牌的 kid 决定怎么回应。
type fakeAPNs struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recorded
	respond  func(kid string) (int, string)
}

type recorded struct {
	proto  int
	path   string
	header http.Header
	body   string
	kid    string
	iss    string
}

func newFakeAPNs(t *testing.T, keys map[string]*ecdsa.PrivateKey) *fakeAPNs {
	f := &fakeAPNs{respond: func(string) (int, string) { return http.StatusOK, "" }}
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := recorded{proto: r.ProtoMajor, path: r.URL.Path, header: r.Header.Clone(), body: string(body)}
		bearer := strings.TrimPrefix(r.Header.Get("authorization"), "bearer ")
		claims := jwt.MapClaims{}
		tok, err := jwt.ParseWithClaims(bearer, claims, func(tk *jwt.Token) (any, error) {
			return &keys[tk.Header["kid"].(string)].PublicKey, nil
		}, jwt.WithValidMethods([]string{"ES256"}))
		if err != nil || !tok.Valid {
			t.Errorf("provider 令牌验签失败：%v", err)
		} else {
			rec.kid, _ = tok.Header["kid"].(string)
			rec.iss, _ = claims["iss"].(string)
		}
		f.mu.Lock()
		f.requests = append(f.requests, rec)
		respond := f.respond
		f.mu.Unlock()
		status, reason := respond(rec.kid)
		w.Header().Set("apns-id", r.Header.Get("apns-id"))
		w.WriteHeader(status)
		if reason != "" {
			io.WriteString(w, `{"reason":"`+reason+`","timestamp":1767225600000}`)
		}
	}))
	f.EnableHTTP2 = true
	f.StartTLS()
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAPNs) setRespond(fn func(kid string) (int, string)) {
	f.mu.Lock()
	f.respond = fn
	f.mu.Unlock()
}

func (f *fakeAPNs) all() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.requests...)
}

func newKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newClient(t *testing.T, prod, dev *fakeAPNs, keys ...Key) *Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(prod.Certificate())
	pool.AddCert(dev.Certificate())
	c, err := New(Config{Keys: keys, ProductionURL: prod.URL, DevelopmentURL: dev.URL, RootCAs: pool,
		Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPushHeadersAndEnvironment(t *testing.T) {
	k1, pem1 := newKey(t)
	keys := map[string]*ecdsa.PrivateKey{"KEY1": k1}
	prod, dev := newFakeAPNs(t, keys), newFakeAPNs(t, keys)
	c := newClient(t, prod, dev, Key{TeamID: "TEAM123456", KeyID: "KEY1", PEM: pem1})

	exp := int64(1767225600)
	n := &Notification{
		ID: "6f1c2a9e-3b7d-4c55-9a10-2e8f4d6b7c01", Token: "abcd" + strings.Repeat("0", 60),
		Topic: "io.movieclaw.app", PushType: "alert", Priority: 10, Expiration: &exp, CollapseID: "k7Qm2xP9",
		Body: []byte(`{"aps":{"badge":1}}`),
	}
	resp, err := c.Push(context.Background(), n)
	if err != nil || resp.StatusCode != http.StatusOK || resp.APNsID != n.ID {
		t.Fatalf("推送失败：%+v %v", resp, err)
	}
	got := prod.all()
	if len(got) != 1 || len(dev.all()) != 0 {
		t.Fatalf("正式环境的推送应发往正式地址：prod=%d dev=%d", len(got), len(dev.all()))
	}
	r := got[0]
	if r.proto != 2 {
		t.Fatalf("应使用 HTTP/2，实际 HTTP/%d", r.proto)
	}
	if r.path != "/3/device/"+n.Token || r.body != string(n.Body) || r.kid != "KEY1" || r.iss != "TEAM123456" {
		t.Fatalf("请求不对：%+v", r)
	}
	for h, want := range map[string]string{
		"apns-id": n.ID, "apns-topic": "io.movieclaw.app", "apns-push-type": "alert",
		"apns-priority": "10", "apns-expiration": "1767225600", "apns-collapse-id": "k7Qm2xP9",
	} {
		if r.header.Get(h) != want {
			t.Errorf("%s = %q，期望 %q", h, r.header.Get(h), want)
		}
	}

	n.Development = true
	if _, err := c.Push(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if len(dev.all()) != 1 {
		t.Fatal("测试环境的推送应发往测试地址")
	}
}

func TestProviderTokenRefresh(t *testing.T) {
	k1, pem1 := newKey(t)
	keys := map[string]*ecdsa.PrivateKey{"KEY1": k1}
	prod, dev := newFakeAPNs(t, keys), newFakeAPNs(t, keys)
	c := newClient(t, prod, dev, Key{TeamID: "TEAM123456", KeyID: "KEY1", PEM: pem1})
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	n := &Notification{ID: "6f1c2a9e-3b7d-4c55-9a10-2e8f4d6b7c01", Token: "ab", Topic: "t", PushType: "alert", Priority: 10}

	c.Push(context.Background(), n)
	now = now.Add(49 * time.Minute)
	c.Push(context.Background(), n)
	now = now.Add(2 * time.Minute) // 距首次签发 51 分钟，应刷新
	c.Push(context.Background(), n)
	got := prod.all()
	a, b, cc := got[0].header.Get("authorization"), got[1].header.Get("authorization"), got[2].header.Get("authorization")
	if a != b || b == cc {
		t.Fatal("provider 令牌应在 50 分钟内复用、超过后刷新")
	}

	// 苹果说令牌过期：强制刷新后重发一次
	first := true
	prod.setRespond(func(string) (int, string) {
		if first {
			first = false
			return http.StatusForbidden, "ExpiredProviderToken"
		}
		return http.StatusOK, ""
	})
	resp, err := c.Push(context.Background(), n)
	if err != nil || resp.StatusCode != http.StatusOK || len(prod.all()) != 5 {
		t.Fatalf("ExpiredProviderToken 后应重发一次：%+v %v", resp, err)
	}
}

func TestKeyFailover(t *testing.T) {
	k1, pem1 := newKey(t)
	k2, pem2 := newKey(t)
	keys := map[string]*ecdsa.PrivateKey{"OLD": k1, "NEW": k2}
	prod, dev := newFakeAPNs(t, keys), newFakeAPNs(t, keys)
	// 旧密钥已在苹果后台吊销
	prod.setRespond(func(kid string) (int, string) {
		if kid == "OLD" {
			return http.StatusForbidden, "InvalidProviderToken"
		}
		return http.StatusOK, ""
	})
	c := newClient(t, prod, dev,
		Key{TeamID: "TEAM123456", KeyID: "OLD", PEM: pem1}, Key{TeamID: "TEAM123456", KeyID: "NEW", PEM: pem2})
	n := &Notification{ID: "6f1c2a9e-3b7d-4c55-9a10-2e8f4d6b7c01", Token: "ab", Topic: "t", PushType: "alert", Priority: 10}

	resp, err := c.Push(context.Background(), n)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("应自动换到新密钥：%+v %v", resp, err)
	}
	c.Push(context.Background(), n)
	var kids []string
	for _, r := range prod.all() {
		kids = append(kids, r.kid)
	}
	if strings.Join(kids, ",") != "OLD,NEW,NEW" {
		t.Fatalf("被拒绝的密钥应暂停使用：%v", kids)
	}
}

func TestErrorResponse(t *testing.T) {
	k1, pem1 := newKey(t)
	keys := map[string]*ecdsa.PrivateKey{"KEY1": k1}
	prod, dev := newFakeAPNs(t, keys), newFakeAPNs(t, keys)
	prod.setRespond(func(string) (int, string) { return http.StatusGone, "Unregistered" })
	c := newClient(t, prod, dev, Key{TeamID: "TEAM123456", KeyID: "KEY1", PEM: pem1})
	resp, err := c.Push(context.Background(), &Notification{ID: "6f1c2a9e-3b7d-4c55-9a10-2e8f4d6b7c01", Token: "ab", Topic: "t", PushType: "alert", Priority: 10})
	if err != nil || resp.StatusCode != http.StatusGone || resp.Reason != "Unregistered" || resp.Timestamp != 1767225600000 {
		t.Fatalf("410 解析不对：%+v %v", resp, err)
	}
}

func TestBadKey(t *testing.T) {
	if _, err := New(Config{Keys: []Key{{KeyID: "X", PEM: []byte("not a key")}}}); err == nil {
		t.Fatal("坏的 .p8 应报错")
	}
	if _, err := New(Config{}); err == nil {
		t.Fatal("没有密钥又不是 dry_run 应报错")
	}
}
