package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims 是实例令牌的声明，格式见 docs/protocol.md「实例令牌」。
type Claims struct {
	jwt.RegisteredClaims
	// Scope 是空格分隔的权限列表，推送需要 push。
	Scope string `json:"scope"`
	// Acct 是账号的不透明 ID，以后按账号汇总限额用。
	Acct string `json:"acct,omitempty"`
	// Lim 是限额表，按名字索引，比如 {"day": 5000, "device_day": 500}。
	Lim map[string]int64 `json:"lim,omitempty"`
}

// RevocationList 是签发方的吊销名单，格式见 docs/protocol.md「对签发方的要求」。
type RevocationList struct {
	Iss         string            `json:"iss"`
	GeneratedAt int64             `json:"generated_at"`
	Entries     []RevocationEntry `json:"entries"`
}

// RevocationEntry 吊销一个实例（sub）或一个账号下的全部实例（acct）。
type RevocationEntry struct {
	Sub       string `json:"sub,omitempty"`
	Acct      string `json:"acct,omitempty"`
	RevokedAt int64  `json:"revoked_at"`
}

// IssuerConfig 是一个受信任的签发方。
type IssuerConfig struct {
	Iss         string
	JWKS        string
	Revocations string
	// Key 是调用吊销名单接口用的中继专用密钥。
	Key string
}

// Issuer 实现 issuer 鉴权：本地验签 + 本地吊销名单。
//
// 公钥和吊销名单每隔 interval 从签发方拉一次，成功后写到磁盘；启动时先读磁盘缓存。
// 所以签发方宕机期间，即使中继重启，推送也照常——这是中继对签发方的全部依赖。
// 实例令牌有效期 24 小时，签发方宕机一天以内推送都不受影响。
type Issuer struct {
	aud      string
	cacheDir string
	interval time.Duration
	client   *http.Client
	log      *slog.Logger
	now      func() time.Time
	issuers  map[string]*issuerState
}

// issuerState 是一个签发方的公钥和吊销名单。
type issuerState struct {
	cfg IssuerConfig

	mu           sync.RWMutex
	keys         map[string]ed25519.PublicKey
	revokedSubs  map[string]bool
	revokedAccts map[string]bool

	// 遇到不认识的 kid 时立刻刷新一次公钥（签发方可能刚轮换密钥），30 秒内最多一次。
	kidMu        sync.Mutex
	lastKidFetch time.Time
}

// NewIssuer 创建 issuer 鉴权，并从磁盘缓存载入上次拉到的公钥和吊销名单。
func NewIssuer(aud string, cfgs []IssuerConfig, cacheDir string, interval time.Duration, log *slog.Logger) (*Issuer, error) {
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建鉴权缓存目录失败：%w", err)
	}
	a := &Issuer{
		aud:      aud,
		cacheDir: cacheDir,
		interval: interval,
		client:   &http.Client{Timeout: 10 * time.Second},
		log:      log,
		now:      time.Now,
		issuers:  map[string]*issuerState{},
	}
	for _, c := range cfgs {
		st := &issuerState{cfg: c}
		a.issuers[c.Iss] = st
		a.loadCache(st)
	}
	return a, nil
}

func (a *Issuer) Mode() string { return "issuer" }

func (a *Issuer) Info() map[string]any {
	var list []string
	for iss := range a.issuers {
		list = append(list, iss)
	}
	slices.Sort(list)
	return map[string]any{"mode": "issuer", "issuers": list}
}

// Ready 表示至少有一个签发方的公钥可用。
func (a *Issuer) Ready() bool {
	for _, st := range a.issuers {
		st.mu.RLock()
		n := len(st.keys)
		st.mu.RUnlock()
		if n > 0 {
			return true
		}
	}
	return false
}

// Run 立刻刷新一次，之后定时刷新，直到 ctx 结束。
func (a *Issuer) Run(ctx context.Context) {
	a.refreshAll(ctx)
	t := time.NewTicker(a.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.refreshAll(ctx)
		}
	}
}

func (a *Issuer) refreshAll(ctx context.Context) {
	for _, st := range a.issuers {
		a.refreshKeys(ctx, st)
		a.refreshRevocations(ctx, st)
	}
}

// Authenticate 验证实例令牌：签名、aud、有效期、吊销名单、push 权限。
func (a *Issuer) Authenticate(ctx context.Context, bearer string) (*Principal, error) {
	if bearer == "" {
		return nil, unauthorized("缺少实例凭证（Authorization: Bearer <令牌>）")
	}
	var claims Claims
	p := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithAudience(a.aud),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
		jwt.WithTimeFunc(a.now),
	)
	_, err := p.ParseWithClaims(bearer, &claims, func(t *jwt.Token) (any, error) { return a.key(ctx, t) })
	if err != nil {
		a.log.Debug("实例凭证验证失败", "error", err)
		return nil, unauthorized("实例凭证无效或已过期")
	}
	if claims.Subject == "" {
		return nil, unauthorized("实例凭证缺少 sub")
	}
	if a.issuers[claims.Issuer].revoked(claims.Subject, claims.Acct) {
		return nil, unauthorized("实例已解绑或被停用，请在实例设置里重新连接")
	}
	if !slices.Contains(strings.Fields(claims.Scope), "push") {
		return nil, forbidden("实例凭证没有 push 权限")
	}
	return &Principal{Instance: claims.Subject, Account: claims.Acct, Limits: claims.Lim}, nil
}

// key 按令牌的 iss 和 kid 找验签公钥。
func (a *Issuer) key(ctx context.Context, t *jwt.Token) (any, error) {
	iss, err := t.Claims.GetIssuer()
	if err != nil {
		return nil, err
	}
	st := a.issuers[iss]
	if st == nil {
		return nil, fmt.Errorf("不认识的签发方 %q", iss)
	}
	kid, _ := t.Header["kid"].(string)
	if k := st.key(kid); k != nil {
		return k, nil
	}
	a.refreshForKid(ctx, st)
	if k := st.key(kid); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("签发方 %s 没有 kid 为 %q 的公钥", iss, kid)
}

func (a *Issuer) refreshForKid(ctx context.Context, st *issuerState) {
	st.kidMu.Lock()
	defer st.kidMu.Unlock()
	if a.now().Sub(st.lastKidFetch) < 30*time.Second {
		return
	}
	st.lastKidFetch = a.now()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	a.refreshKeys(ctx, st)
}

func (a *Issuer) refreshKeys(ctx context.Context, st *issuerState) {
	b, err := a.fetch(ctx, st.cfg.JWKS, "")
	if err != nil {
		a.log.Warn("拉取签发方公钥失败，继续使用已有的公钥", "iss", st.cfg.Iss, "error", err)
		return
	}
	keys, err := parseJWKS(b)
	if err != nil {
		a.log.Warn("签发方返回的公钥无法使用，继续使用已有的公钥", "iss", st.cfg.Iss, "error", err)
		return
	}
	st.mu.Lock()
	st.keys = keys
	st.mu.Unlock()
	a.writeCache(a.cachePath(st, "jwks"), b)
}

func (a *Issuer) refreshRevocations(ctx context.Context, st *issuerState) {
	b, err := a.fetch(ctx, st.cfg.Revocations, st.cfg.Key)
	if err != nil {
		a.log.Warn("拉取吊销名单失败，继续使用已有的名单", "iss", st.cfg.Iss, "error", err)
		return
	}
	subs, accts, err := parseRevocations(b, st.cfg.Iss)
	if err != nil {
		a.log.Warn("签发方返回的吊销名单无法使用，继续使用已有的名单", "iss", st.cfg.Iss, "error", err)
		return
	}
	st.setRevocations(subs, accts)
	a.writeCache(a.cachePath(st, "revocations"), b)
}

func (a *Issuer) fetch(ctx context.Context, url, bearer string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s 返回 HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// cachePath 按签发方地址的哈希命名缓存文件，一个签发方一组。
func (a *Issuer) cachePath(st *issuerState, kind string) string {
	sum := sha256.Sum256([]byte(st.cfg.Iss))
	return filepath.Join(a.cacheDir, hex.EncodeToString(sum[:8])+"."+kind+".json")
}

func (a *Issuer) loadCache(st *issuerState) {
	if b, err := os.ReadFile(a.cachePath(st, "jwks")); err == nil {
		if keys, err := parseJWKS(b); err == nil {
			st.keys = keys
			a.log.Info("已从磁盘缓存载入签发方公钥", "iss", st.cfg.Iss, "keys", len(keys))
		} else {
			a.log.Warn("磁盘上的公钥缓存无法使用", "iss", st.cfg.Iss, "error", err)
		}
	}
	if b, err := os.ReadFile(a.cachePath(st, "revocations")); err == nil {
		if subs, accts, err := parseRevocations(b, st.cfg.Iss); err == nil {
			st.setRevocations(subs, accts)
		} else {
			a.log.Warn("磁盘上的吊销名单缓存无法使用", "iss", st.cfg.Iss, "error", err)
		}
	}
}

func (a *Issuer) writeCache(path string, b []byte) {
	if err := writeFileAtomic(path, b); err != nil {
		a.log.Error("写鉴权缓存失败，签发方宕机时重启中继将无法验签", "path", path, "error", err)
	}
}

func (st *issuerState) key(kid string) ed25519.PublicKey {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.keys[kid]
}

func (st *issuerState) revoked(sub, acct string) bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.revokedSubs[sub] || (acct != "" && st.revokedAccts[acct])
}

func (st *issuerState) setRevocations(subs, accts map[string]bool) {
	st.mu.Lock()
	st.revokedSubs, st.revokedAccts = subs, accts
	st.mu.Unlock()
}

// parseJWKS 取出 JWKS 里的 Ed25519 公钥（kty=OKP、crv=Ed25519），其他类型的键忽略。
func parseJWKS(b []byte) (map[string]ed25519.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, fmt.Errorf("JWKS 不是合法的 JSON：%w", err)
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			continue
		}
		keys[k.Kid] = ed25519.PublicKey(x)
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS 里没有可用的 Ed25519 公钥")
	}
	return keys, nil
}

func parseRevocations(b []byte, iss string) (subs, accts map[string]bool, err error) {
	var list RevocationList
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, nil, fmt.Errorf("吊销名单不是合法的 JSON：%w", err)
	}
	if list.Iss != "" && list.Iss != iss {
		return nil, nil, fmt.Errorf("吊销名单的 iss 是 %q，和配置的 %q 不一致", list.Iss, iss)
	}
	subs, accts = map[string]bool{}, map[string]bool{}
	for _, e := range list.Entries {
		if e.Sub != "" {
			subs[e.Sub] = true
		}
		if e.Acct != "" {
			accts[e.Acct] = true
		}
	}
	return subs, accts, nil
}

// writeFileAtomic 先写临时文件再改名，中途断电也不会留下半个文件。
func writeFileAtomic(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
