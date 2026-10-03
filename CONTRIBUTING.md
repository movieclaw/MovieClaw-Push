# 参与贡献 / Contributing

欢迎提 Issue 和 PR。

- **改协议先开 Issue 讨论**：[docs/protocol.md](docs/protocol.md) 是实例和所有中继实现共同遵守的契约，
  加字段、加类型、加结果码都不能让已经装好的老版本实例出错。改协议要同时改一致性测试（`protocol/protocoltest`）。
- **提交前**：`go vet ./... && go test -race ./...`（会编译真实的程序跑一致性测试）。
- **PR 怎么合并**：这个仓库的 `main` 由我们的内部仓库同步生成。PR 评审通过后，我们把你的提交引入内部仓库
  （作者仍然是你），同步回 `main` 后关闭 PR，并附上合并后的提交链接。所以 PR 会显示 Closed 而不是 Merged，这是正常的。
- 安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。

Issues and pull requests are welcome. Please open an issue before changing the protocol
([docs/protocol.md](docs/protocol.md)): new fields, types and result codes must never break instances already in
the wild. Run `go vet ./... && go test -race ./...` before submitting.

`main` is synced from our internal repository. Once a PR is approved, we import your commits there (you stay the
author), sync them back to `main`, and close the PR with a link to the resulting commit. It will show as Closed
rather than Merged; that is expected.
