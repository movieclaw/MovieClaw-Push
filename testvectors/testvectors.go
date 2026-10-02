// Package testvectors 是推送中继协议的测试向量，签发方和中继各自用它核对自己的实现
// （说明见 docs/protocol.md「测试向量」）。
//
// 它是中继对外发布的契约，不是内部实现：令牌签发方（比如 MovieClaw 的 api）在测试里
// 引用它，核对自己签发的实例令牌和向量一致，也就能通过中继的验证。改了向量要重新生成：
// go test ./internal/auth -run TestVectors -update
package testvectors

import _ "embed"

// InstanceToken 是实例令牌的测试向量（instance-token.json）。
//
//go:embed instance-token.json
var InstanceToken []byte
