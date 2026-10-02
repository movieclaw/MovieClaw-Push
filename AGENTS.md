# movieclaw-push

MovieClaw 的推送中继：把实例发来的密文推送转发给 APNs。开源（Apache-2.0），协议见 `docs/protocol.md`。

## 命令

```bash
go test ./...
go test ./internal/auth -run TestVectors -update   # 改了令牌格式后重新生成测试向量
```

## 必须遵守

1. 这是独立项目：不能引用本目录以外的任何代码和文件，必须能单独构建（`GOWORK=off go test ./...`）。
2. 不出现账号等云端概念：中继只认实例令牌里的声明。
3. 改接口先改 `docs/protocol.md`；加字段、加类型、加结果码都不能让老版本实例出错。
4. 明文里只允许控制类字段，不保存设备令牌和推送内容；日志不记内容和完整令牌。
5. `testvectors` 是对外发布的契约：改了令牌格式要重新生成向量，并通知签发方。
6. 代码注释和日志用中文。
