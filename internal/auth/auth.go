// Package auth 是中继的两种鉴权方式：static、none。
//
//   - static：令牌由中继自己发（movieclaw-push token create），给自签 App 的自建用户用。
//   - none：不鉴权、只按设备限流，只在内网或运营方停运时用。
package auth

import (
	"context"
	"net/http"

	"github.com/movieclaw/movieclaw-push/protocol"
)

// Principal 是通过鉴权的调用方。
type Principal struct {
	// Instance 是计数、限额和日志用的实例标识：static 模式为令牌 ID，none 模式为空。
	Instance string
}

// Authenticator 是一种鉴权方式。
type Authenticator interface {
	// Mode 返回 static 或 none，写进 /v1/info。
	Mode() string
	// Authenticate 校验 Authorization: Bearer 后面的凭证。失败时返回 *protocol.RequestError：
	// 401 凭证无效或已吊销，403 缺少权限。
	Authenticate(ctx context.Context, bearer string) (*Principal, error)
	// Info 是写进 /v1/info 的鉴权信息。
	Info() map[string]any
}

func unauthorized(msg string) *protocol.RequestError {
	return &protocol.RequestError{Status: http.StatusUnauthorized, Code: protocol.ErrUnauthorized, Message: msg}
}

func forbidden(msg string) *protocol.RequestError {
	return &protocol.RequestError{Status: http.StatusForbidden, Code: protocol.ErrForbidden, Message: msg}
}

// None 不鉴权：任何人都能调用，只靠按设备的每日上限防刷。
type None struct{}

func (None) Mode() string { return "none" }

func (None) Authenticate(context.Context, string) (*Principal, error) { return &Principal{}, nil }

func (None) Info() map[string]any { return map[string]any{"mode": "none"} }
