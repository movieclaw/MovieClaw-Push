# movieclaw-push

MovieClaw 的推送中继：把实例发来的密文推送转发给 APNs。开源（Apache-2.0），协议见 `docs/protocol.md`。
`protocol`、`apns`、`protocol/protocoltest` 是公开的 Go 包，别的中继实现会调用它们。

## 命令

```bash
go test ./...                                          # 含编译真实的程序跑一致性测试
go test ./cmd/movieclaw-push -run TestConformance -v   # 只跑一致性测试
```

## 必须遵守

1. 这是独立项目：不能引用本目录以外的任何代码和文件，必须能单独构建（`GOWORK=off go test ./...`）。
2. 不出现账号等云端概念，也不为别的实现加扩展点或钩子：别的中继实现只调用 `protocol`、`apns` 这两个公开的包。
3. 改协议先改 `docs/protocol.md` 和一致性测试（`protocol/protocoltest`），再改 `protocol` 包；加字段、加类型、加结果码都不能让老版本实例出错。
4. 明文里只允许控制类字段，不保存设备令牌和推送内容；日志不记内容和完整令牌。
5. `protocol`、`apns`、`protocoltest` 是公开的 Go 包，改它们的导出接口要当作破坏兼容来看。
6. 代码注释和日志用中文。
