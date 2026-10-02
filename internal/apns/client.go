// Package apns 是用标准库 HTTP/2 写的 APNs 客户端。
//
// 不用第三方 APNs 库：握着 .p8 密钥的服务依赖越少越好，而且需要的功能很少——
//   - 正式环境和测试环境各一条 HTTP/2 长连接（Go 的连接池按主机名复用，天然如此），
//     空闲时发 PING 保活；
//   - provider 令牌（ES256 JWT）每 50 分钟刷新一次，苹果要求在 20–60 分钟之间；
//   - 可以挂多把 .p8：第一把优先，苹果返回 InvalidProviderToken 时自动换下一把，
//     换密钥（先加新密钥、再去苹果后台吊销旧的）时推送不中断。
package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 苹果的接口地址。
const (
	ProductionURL  = "https://api.push.apple.com"
	DevelopmentURL = "https://api.sandbox.push.apple.com"
)

const (
	// tokenTTL 是 provider 令牌的刷新周期。
	tokenTTL = 50 * time.Minute
	// keyCooldown 是一把密钥被苹果拒绝后暂停使用的时间。
	keyCooldown = 10 * time.Minute
)

// Key 是一把 APNs 鉴权密钥。
type Key struct {
	TeamID string
	KeyID  string
	// PEM 是 .p8 文件的内容。
	PEM []byte
}

// Config 是客户端配置。
type Config struct {
	Keys           []Key
	ProductionURL  string // 为空时用苹果的正式地址
	DevelopmentURL string // 为空时用苹果的测试地址
	RootCAs        *x509.CertPool
	// DryRun 为 true 时不连接苹果，直接返回成功。
	DryRun bool
	Log    *slog.Logger
}

// Notification 是一条要发给苹果的推送。
type Notification struct {
	ID          string // apns-id，原样用实例生成的追踪 id
	Token       string
	Topic       string // 已补上类型后缀的完整 topic
	PushType    string
	Priority    int
	Expiration  *int64
	CollapseID  string
	Development bool
	Body        []byte
}

// Response 是苹果的返回。
type Response struct {
	StatusCode int
	// Reason 是苹果给的错误原因，如 BadDeviceToken、Unregistered。
	Reason string
	// Timestamp 是 410 时苹果给的令牌失效时间（Unix 毫秒）。
	Timestamp int64
	APNsID    string
}

// Client 是 APNs 客户端，可以并发使用。
type Client struct {
	signers []*signer
	http    *http.Client
	prodURL string
	devURL  string
	dryRun  bool
	log     *slog.Logger
	now     func() time.Time
}

// New 创建客户端并解析全部 .p8 密钥。
func New(cfg Config) (*Client, error) {
	c := &Client{
		prodURL: cfg.ProductionURL,
		devURL:  cfg.DevelopmentURL,
		dryRun:  cfg.DryRun,
		log:     cfg.Log,
		now:     time.Now,
	}
	if c.prodURL == "" {
		c.prodURL = ProductionURL
	}
	if c.devURL == "" {
		c.devURL = DevelopmentURL
	}
	for _, k := range cfg.Keys {
		key, err := parseP8(k.PEM)
		if err != nil {
			return nil, fmt.Errorf("APNs 密钥 %s 无法使用：%w", k.KeyID, err)
		}
		c.signers = append(c.signers, &signer{teamID: k.TeamID, keyID: k.KeyID, key: key})
	}
	if len(c.signers) == 0 && !c.dryRun {
		return nil, errors.New("没有可用的 APNs 密钥")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12},
		Proxy:           http.ProxyFromEnvironment,
		IdleConnTimeout: time.Hour,
		HTTP2: &http.HTTP2Config{
			// 连接空闲 1 分钟就发 PING，及时发现被中间设备掐断的长连接
			SendPingTimeout: time.Minute,
			PingTimeout:     15 * time.Second,
		},
	}
	tr.Protocols = new(http.Protocols)
	tr.Protocols.SetHTTP2(true) // APNs 只支持 HTTP/2
	c.http = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	return c, nil
}

// Push 发送一条推送。网络错误时返回 error；苹果的任何回应（包括拒绝）都放在 Response 里。
func (c *Client) Push(ctx context.Context, n *Notification) (*Response, error) {
	if c.dryRun {
		c.log.Info("dry_run：没有真正发给苹果", "id", n.ID, "topic", n.Topic, "push_type", n.PushType,
			"priority", n.Priority, "development", n.Development, "bytes", len(n.Body))
		return &Response{StatusCode: http.StatusOK, APNsID: n.ID}, nil
	}
	var last *Response
	for _, s := range c.order() {
		resp, err := c.send(ctx, s, n)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusForbidden && resp.Reason == "ExpiredProviderToken" {
			// 苹果认为令牌过期（比如机器时钟漂移），强制换一个新令牌重发一次
			s.reset()
			if resp, err = c.send(ctx, s, n); err != nil {
				return nil, err
			}
		}
		if resp.StatusCode == http.StatusForbidden && resp.Reason == "InvalidProviderToken" {
			s.markFailed(c.now())
			c.log.Error("苹果拒绝了这把 APNs 密钥，换下一把；请检查 team_id、key_id 是否填对、密钥是否已被吊销",
				"key_id", s.keyID, "team_id", s.teamID)
			last = resp
			continue
		}
		return resp, nil
	}
	return last, nil
}

// order 返回本次尝试的密钥顺序：没被拒绝过的在前，被拒绝的放最后兜底。
func (c *Client) order() []*signer {
	now := c.now()
	var ok, failed []*signer
	for _, s := range c.signers {
		if s.failedSince(now) {
			failed = append(failed, s)
		} else {
			ok = append(ok, s)
		}
	}
	return append(ok, failed...)
}

func (c *Client) send(ctx context.Context, s *signer, n *Notification) (*Response, error) {
	bearer, err := s.bearer(c.now())
	if err != nil {
		return nil, err
	}
	base := c.prodURL
	if n.Development {
		base = c.devURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+n.Token, bytes.NewReader(n.Body))
	if err != nil {
		return nil, err
	}
	h := req.Header
	h.Set("authorization", "bearer "+bearer)
	h.Set("content-type", "application/json")
	h.Set("apns-id", n.ID)
	h.Set("apns-topic", n.Topic)
	h.Set("apns-push-type", n.PushType)
	h.Set("apns-priority", strconv.Itoa(n.Priority))
	if n.Expiration != nil {
		h.Set("apns-expiration", strconv.FormatInt(*n.Expiration, 10))
	}
	if n.CollapseID != "" {
		h.Set("apns-collapse-id", n.CollapseID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	out := &Response{StatusCode: resp.StatusCode, APNsID: resp.Header.Get("apns-id")}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Reason    string `json:"reason"`
			Timestamp int64  `json:"timestamp"`
		}
		_ = json.Unmarshal(body, &e)
		out.Reason, out.Timestamp = e.Reason, e.Timestamp
	}
	return out, nil
}

// signer 持有一把 .p8 密钥和它当前的 provider 令牌。
type signer struct {
	teamID string
	keyID  string
	key    *ecdsa.PrivateKey

	mu          sync.Mutex
	token       string
	issuedAt    time.Time
	failedUntil time.Time
}

func (s *signer) bearer(now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && now.Sub(s.issuedAt) < tokenTTL {
		return s.token, nil
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": s.teamID, "iat": now.Unix()})
	t.Header["kid"] = s.keyID
	signed, err := t.SignedString(s.key)
	if err != nil {
		return "", fmt.Errorf("签发 APNs provider 令牌失败：%w", err)
	}
	s.token, s.issuedAt = signed, now
	return signed, nil
}

func (s *signer) reset() {
	s.mu.Lock()
	s.token = ""
	s.mu.Unlock()
}

func (s *signer) markFailed(now time.Time) {
	s.mu.Lock()
	s.failedUntil = now.Add(keyCooldown)
	s.token = ""
	s.mu.Unlock()
}

func (s *signer) failedSince(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Before(s.failedUntil)
}

// parseP8 解析苹果下载的 .p8 文件（PKCS#8 封装的 P-256 私钥）。
func parseP8(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("不是 PEM 格式，请确认用的是从苹果后台下载的 .p8 文件")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败：%w", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("不是 ECDSA 私钥")
	}
	return ec, nil
}
