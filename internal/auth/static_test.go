package auth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStaticTokenLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	s := NewStatic(path)
	ctx := context.Background()

	if _, err := s.Authenticate(ctx, "mcpush_nope_nope"); !isCode(err, "unauthorized") {
		t.Fatalf("没有令牌文件时应拒绝：%v", err)
	}

	token, rec, err := CreateStaticToken(path, "客厅服务器", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, StaticPrefix+rec.ID+"_") {
		t.Fatalf("令牌格式不对：%s", token)
	}
	s.checked = time.Time{} // 跳过「每秒最多检查一次文件」
	p, err := s.Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("新令牌应该能用：%v", err)
	}
	if p.Instance != rec.ID {
		t.Fatalf("实例标识应是令牌 ID，实际 %q", p.Instance)
	}
	if _, err := s.Authenticate(ctx, token+"x"); !isCode(err, "unauthorized") {
		t.Fatalf("改过的令牌应被拒绝：%v", err)
	}
	if _, err := s.Authenticate(ctx, "Bearer "+token); !isCode(err, "unauthorized") {
		t.Fatalf("格式不对的令牌应被拒绝：%v", err)
	}

	if err := RevokeStaticToken(path, rec.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.checked = time.Time{}
	if _, err := s.Authenticate(ctx, token); !isCode(err, "unauthorized") {
		t.Fatalf("吊销后应被拒绝：%v", err)
	}
	if err := RevokeStaticToken(path, "missing", time.Now()); err == nil {
		t.Fatal("吊销不存在的令牌应报错")
	}
	list, err := ReadStaticTokens(path)
	if err != nil || len(list) != 1 || list[0].RevokedAt == nil {
		t.Fatalf("令牌文件内容不对：%+v %v", list, err)
	}
}

func isCode(err error, code string) bool {
	var ae *Error
	return errors.As(err, &ae) && ae.Code == code
}
