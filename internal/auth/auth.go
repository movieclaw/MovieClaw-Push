// Package auth 是中继的三种鉴权方式：issuer、static、none。
//
// 中继不相信实例声称的任何东西，只检查自己能验证的：
//   - issuer：实例令牌是签发方（官方为 MovieClaw 的 api）用 Ed25519 签的 JWT，中继用
//     本地缓存的公钥验签，再查本地缓存的吊销名单。签发方宕机不影响验签。
//   - static：令牌由中继自己发（movieclaw-push token create），给自签 App 的自建用户用。
//   - none：不鉴权、只按设备限流，只作运营方停运时的退路。
//
// 三种方式由配置切换，同一份代码。
package auth

import (
	"context"
	"net/http"

	"github.com/movieclaw/movieclaw-push/protocol"
)

// Principal 是通过鉴权的调用方。
type Principal struct {
	// Instance 是计数、限额和日志用的实例标识：issuer 模式为令牌的 sub，static 模式为
	// 令牌 ID，none 模式为空。
	Instance string
	// Account 是令牌里的 acct（账号的不透明 ID），以后按账号汇总限额用。
	Account string
	// Limits 是令牌里的 lim，没有的键用配置里的默认值。
	Limits map[string]int64
}

// Authenticator 是一种鉴权方式。
type Authenticator interface {
	// Mode 返回 issuer、static 或 none，写进 /v1/info。
	Mode() string
	// Authenticate 校验 Authorization: Bearer 后面的凭证。失败时返回 *protocol.RequestError：
	// 401 凭证无效或已吊销，403 缺少权限。
	Authenticate(ctx context.Context, bearer string) (*Principal, error)
	// Info 是写进 /v1/info 的鉴权信息。
	Info() map[string]any
	// Ready 表示能不能验证凭证（issuer 模式下要先拿到公钥）。
	Ready() bool
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

func (None) Ready() bool { return true }
