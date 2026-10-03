package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/movieclaw/movieclaw-push/protocol"
)

// StaticPrefix 是静态令牌的前缀，方便在日志、代码仓库里识别出泄露的令牌。
const StaticPrefix = "mcpush_"

// StaticToken 是令牌文件里的一条记录。文件里只存令牌的 SHA-256，令牌本身只在创建时显示一次。
type StaticToken struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Hash      string     `json:"hash"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type tokenFile struct {
	Tokens []StaticToken `json:"tokens"`
}

// Static 实现 static 鉴权：令牌由中继自己发（movieclaw-push token create），存在
// data_dir/tokens.json。管理命令改这个文件，运行中的中继发现文件变了就重新读，不用重启。
//
// 令牌格式是 mcpush_<ID>_<密钥>，ID 用来查记录，也是计数和日志里的实例标识。
type Static struct {
	path string

	mu      sync.Mutex
	checked time.Time
	modTime time.Time
	size    int64
	tokens  map[string]StaticToken
}

// NewStatic 创建 static 鉴权，path 是令牌文件。
func NewStatic(path string) *Static { return &Static{path: path} }

func (s *Static) Mode() string { return "static" }

func (s *Static) Info() map[string]any { return map[string]any{"mode": "static"} }

func (s *Static) Authenticate(_ context.Context, bearer string) (*Principal, error) {
	id, ok := parseStaticToken(bearer)
	if !ok {
		return nil, unauthorized("缺少令牌或令牌格式不对（应以 " + StaticPrefix + " 开头）")
	}
	tokens, err := s.load()
	if err != nil {
		return nil, &protocol.RequestError{Status: http.StatusInternalServerError, Code: protocol.ErrInternal, Message: "读取令牌文件失败：" + err.Error()}
	}
	t, ok := tokens[id]
	sum := sha256.Sum256([]byte(bearer))
	if !ok || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(t.Hash)) != 1 {
		return nil, unauthorized("令牌无效")
	}
	if t.RevokedAt != nil {
		return nil, unauthorized("令牌已吊销")
	}
	return &Principal{Instance: t.ID}, nil
}

// load 返回当前的令牌表；每秒最多检查一次文件有没有变。
func (s *Static) load() (map[string]StaticToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokens != nil && time.Since(s.checked) < time.Second {
		return s.tokens, nil
	}
	s.checked = time.Now()
	fi, err := os.Stat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		s.tokens = map[string]StaticToken{}
		return s.tokens, nil
	}
	if err != nil {
		return nil, err
	}
	if s.tokens != nil && fi.ModTime().Equal(s.modTime) && fi.Size() == s.size {
		return s.tokens, nil
	}
	list, err := ReadStaticTokens(s.path)
	if err != nil {
		return nil, err
	}
	m := make(map[string]StaticToken, len(list))
	for _, t := range list {
		m[t.ID] = t
	}
	s.tokens, s.modTime, s.size = m, fi.ModTime(), fi.Size()
	return m, nil
}

func parseStaticToken(tok string) (id string, ok bool) {
	rest, ok := strings.CutPrefix(tok, StaticPrefix)
	if !ok {
		return "", false
	}
	id, secret, ok := strings.Cut(rest, "_")
	return id, ok && id != "" && secret != ""
}

// ReadStaticTokens 读令牌文件；文件不存在时返回空列表。
func ReadStaticTokens(path string) ([]StaticToken, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f tokenFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("令牌文件 %s 格式错误：%w", path, err)
	}
	return f.Tokens, nil
}

// CreateStaticToken 生成一个新令牌并写进令牌文件，返回令牌明文（只此一次）。
func CreateStaticToken(path, name string, now time.Time) (string, StaticToken, error) {
	list, err := ReadStaticTokens(path)
	if err != nil {
		return "", StaticToken{}, err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	random := func(n int) string {
		b := make([]byte, n)
		rand.Read(b)
		return strings.ToLower(enc.EncodeToString(b))
	}
	id := random(5)
	token := StaticPrefix + id + "_" + random(32)
	sum := sha256.Sum256([]byte(token))
	rec := StaticToken{ID: id, Name: name, Hash: hex.EncodeToString(sum[:]), CreatedAt: now.UTC()}
	if err := writeStaticTokens(path, append(list, rec)); err != nil {
		return "", StaticToken{}, err
	}
	return token, rec, nil
}

// RevokeStaticToken 吊销一个令牌。记录保留，便于以后查日志时知道这个 ID 是谁。
func RevokeStaticToken(path, id string, now time.Time) error {
	list, err := ReadStaticTokens(path)
	if err != nil {
		return err
	}
	for i := range list {
		if list[i].ID == id {
			if list[i].RevokedAt == nil {
				t := now.UTC()
				list[i].RevokedAt = &t
			}
			return writeStaticTokens(path, list)
		}
	}
	return fmt.Errorf("没有 ID 为 %s 的令牌", id)
}

func writeStaticTokens(path string, list []StaticToken) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(tokenFile{Tokens: list}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b)
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
