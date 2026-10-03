package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/movieclaw/movieclaw-push/protocol"
)

// 实例令牌的测试向量（testvectors/instance-token.json，对外以 testvectors 包发布）是中继和签发方之间的契约：
//   - 中继必须对每个用例给出 expect 的结论（本文件的 TestVectors）；
//   - 签发方用同一把密钥、同样的声明签出的令牌，头和声明必须和 issue 一致
//     （MovieClaw 的 api 在 internal/token 的测试里核对）。
//
// 改了向量要重新生成：go test ./internal/auth -run TestVectors -update
var update = flag.Bool("update", false, "重新生成 testvectors/instance-token.json")

const vectorPath = "../../testvectors/instance-token.json"

type vectorFile struct {
	Description    string          `json:"description"`
	Algorithm      string          `json:"algorithm"`
	PrivateKeySeed string          `json:"private_key_seed"`
	Now            int64           `json:"now"`
	Iss            string          `json:"iss"`
	Aud            string          `json:"aud"`
	JWKS           json.RawMessage `json:"jwks"`
	Revocations    RevocationList  `json:"revocations"`
	Issue          vectorIssue     `json:"issue"`
	Cases          []vectorCase    `json:"cases"`
}

type vectorIssue struct {
	Description string         `json:"description"`
	Header      map[string]any `json:"header"`
	Claims      map[string]any `json:"claims"`
	Token       string         `json:"token"`
}

type vectorCase struct {
	Name     string           `json:"name"`
	Token    string           `json:"token"`
	Expect   string           `json:"expect"` // ok / unauthorized / forbidden
	Instance string           `json:"instance,omitempty"`
	Account  string           `json:"account,omitempty"`
	Limits   map[string]int64 `json:"limits,omitempty"`
}

func TestVectors(t *testing.T) {
	if *update {
		generateVectors(t)
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}

	// 把向量里的公钥和吊销名单放进缓存目录，顺带验证「签发方宕机时从磁盘缓存验签」
	dir := t.TempDir()
	st := &issuerState{cfg: IssuerConfig{Iss: v.Iss}}
	a := &Issuer{cacheDir: dir}
	revocations, _ := json.Marshal(v.Revocations)
	if err := os.WriteFile(a.cachePath(st, "jwks"), v.JWKS, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.cachePath(st, "revocations"), revocations, 0o600); err != nil {
		t.Fatal(err)
	}
	iss, err := NewIssuer(v.Aud, []IssuerConfig{{Iss: v.Iss, JWKS: "https://unreachable.invalid/jwks.json",
		Revocations: "https://unreachable.invalid/revocations"}}, dir, time.Hour, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	iss.now = func() time.Time { return time.Unix(v.Now, 0) }
	iss.client = &http.Client{Transport: offline{}}
	if !iss.Ready() {
		t.Fatal("没有从磁盘缓存载入公钥")
	}

	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			p, err := iss.Authenticate(context.Background(), c.Token)
			got := "ok"
			var ae *protocol.RequestError
			if errors.As(err, &ae) {
				got = ae.Code
			} else if err != nil {
				t.Fatalf("意外的错误：%v", err)
			}
			if got != c.Expect {
				t.Fatalf("期望 %s，实际 %s（%v）", c.Expect, got, err)
			}
			if got == "ok" && (p.Instance != c.Instance || p.Account != c.Account || len(p.Limits) != len(c.Limits)) {
				t.Fatalf("鉴权结果不对：%+v", p)
			}
		})
	}
}

// offline 让测试里「遇到不认识的 kid 时刷新公钥」直接失败，不访问网络。
type offline struct{}

func (offline) RoundTrip(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF }

func generateVectors(t *testing.T) {
	// RFC 8032 第 7.1 节测试 1 的私钥种子，谁都能核对
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub)
	// kid 是 RFC 7638 JWK 指纹：成员按字典序、无空白
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
	kid := base64.RawURLEncoding.EncodeToString(sum[:])

	otherSeed := sha256.Sum256([]byte("movieclaw-push test vector: other key"))
	other := ed25519.NewKeyFromSeed(otherSeed[:])

	const (
		iss  = "https://api.example.com"
		aud  = "https://push.example.com"
		sub  = "0b7c6f8e-3d2a-4e5f-9a1b-2c3d4e5f6a7b"
		acct = "6a0f4c1e-8b2d-4f3a-9e5c-7d1b2a3c4e5f"
	)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	iat := now - 60
	base := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": iss, "sub": sub, "aud": aud, "iat": iat, "exp": iat + 86400,
			"scope": "push", "acct": acct, "lim": map[string]int64{"day": 5000, "device_day": 500},
		}
	}
	sign := func(c jwt.MapClaims, k ed25519.PrivateKey, kid string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
		tok.Header["kid"] = kid
		s, err := tok.SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	with := func(edit func(jwt.MapClaims)) string {
		c := base()
		edit(c)
		return sign(c, key, kid)
	}
	b64 := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}

	valid := sign(base(), key, kid)
	parts := strings.Split(valid, ".")
	tamperedClaims := base()
	tamperedClaims["lim"] = map[string]int64{"day": 1000000}
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, base())
	hs.Header["kid"] = kid
	hsToken, _ := hs.SignedString([]byte(x))

	ok := func(name, token string, limits map[string]int64) vectorCase {
		return vectorCase{Name: name, Token: token, Expect: "ok", Instance: sub, Account: acct, Limits: limits}
	}
	lim := map[string]int64{"day": 5000, "device_day": 500}
	v := vectorFile{
		Description: "MovieClaw 推送中继的实例令牌测试向量。中继必须对每个用例给出 expect 的结论；" +
			"签发方用 private_key_seed 和 issue.claims 签出的令牌，头和声明必须和 issue 一致。说明见 docs/protocol.md「测试向量」。",
		Algorithm:      "EdDSA (Ed25519, RFC 8037)",
		PrivateKeySeed: hex.EncodeToString(seed),
		Now:            now,
		Iss:            iss,
		Aud:            aud,
		JWKS: mustRaw(map[string]any{"keys": []map[string]string{
			{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid, "alg": "EdDSA", "use": "sig"},
		}}),
		Revocations: RevocationList{Iss: iss, GeneratedAt: now, Entries: []RevocationEntry{
			{Sub: "9f1e2d3c-4b5a-4968-8776-5a4b3c2d1e0f", RevokedAt: now - 300},
			{Acct: "1d2c3b4a-5e6f-4a7b-8c9d-0e1f2a3b4c5d", RevokedAt: now - 300},
		}},
		Issue: vectorIssue{
			Description: "签发方的参考输出：now 前 60 秒签发、有效期 24 小时",
			Header:      map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": kid},
			Claims:      base(),
			Token:       valid,
		},
		Cases: []vectorCase{
			ok("valid", valid, lim),
			ok("aud_as_array", with(func(c jwt.MapClaims) { c["aud"] = []string{aud} }), lim),
			ok("multiple_scopes", with(func(c jwt.MapClaims) { c["scope"] = "control push" }), lim),
			ok("without_lim", with(func(c jwt.MapClaims) { delete(c, "lim") }), nil),
			{Name: "expired", Expect: "unauthorized", Token: with(func(c jwt.MapClaims) {
				c["iat"], c["exp"] = now-90000, now-3600
			})},
			{Name: "not_yet_valid", Expect: "unauthorized", Token: with(func(c jwt.MapClaims) { c["nbf"] = now + 3600 })},
			{Name: "without_exp", Expect: "unauthorized", Token: with(func(c jwt.MapClaims) { delete(c, "exp") })},
			{Name: "wrong_aud", Expect: "unauthorized", Token: with(func(c jwt.MapClaims) { c["aud"] = "https://push.other.example" })},
			{Name: "unknown_iss", Expect: "unauthorized", Token: with(func(c jwt.MapClaims) { c["iss"] = "https://evil.example" })},
			{Name: "without_sub", Expect: "unauthorized", Token: with(func(c jwt.MapClaims) { delete(c, "sub") })},
			{Name: "unknown_kid", Expect: "unauthorized", Token: sign(base(), other, "unknown-kid")},
			{Name: "wrong_key", Expect: "unauthorized", Token: sign(base(), other, kid)},
			{Name: "tampered_claims", Expect: "unauthorized", Token: parts[0] + "." + b64(tamperedClaims) + "." + parts[2]},
			{Name: "alg_none", Expect: "unauthorized", Token: b64(map[string]string{"alg": "none", "typ": "JWT"}) + "." + parts[1] + "."},
			{Name: "alg_hs256_with_public_key", Expect: "unauthorized", Token: hsToken},
			{Name: "missing_push_scope", Expect: "forbidden", Token: with(func(c jwt.MapClaims) { c["scope"] = "control" })},
			{Name: "revoked_instance", Expect: "unauthorized", Token: with(func(c jwt.MapClaims) {
				c["sub"] = "9f1e2d3c-4b5a-4968-8776-5a4b3c2d1e0f"
			})},
			{Name: "revoked_account", Expect: "unauthorized", Token: with(func(c jwt.MapClaims) {
				c["acct"] = "1d2c3b4a-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
			})},
		},
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(vectorPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorPath, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRaw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
