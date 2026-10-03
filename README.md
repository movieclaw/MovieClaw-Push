# movieclaw-push

MovieClaw 的推送中继：把 MovieClaw 实例发来的**密文**推送转发给 Apple 推送通知服务（APNs）。

- **看不到内容**：推送内容在实例上端到端加密，中继只转发密文；明文里只允许控制类字段（角标、优先级……），任何能看出语义的文字都会被拒绝。
- **不保存设备令牌、不保存推送内容**：没有数据库，只在本地 SQLite 里按「实例 × 天」记推送条数，用来执行限额。
- **签发方宕机也不影响推送**：官方部署时，实例令牌由 MovieClaw 官方 api 签发、中继本地验签，公钥和吊销名单落盘缓存。
- **官方中继 = 本仓库 + 官方配置 + 官方 .p8**，没有私有分支。用自己的开发者账号和 Bundle ID 打包 App 的用户，可以自己部署一个。

协议：[docs/protocol.md](docs/protocol.md)。许可证：Apache-2.0。

## 自建部署（自签 App）

需要：一个 Apple 开发者账号、你自己打包的 MovieClaw App 的 Bundle ID、一把 APNs 鉴权密钥（.p8，在开发者后台 Certificates, Identifiers & Profiles → Keys 创建，勾选 Apple Push Notifications service）。

1. 准备目录：

   ```
   movieclaw-push/
     config.yaml              从 examples/config.yaml 复制后修改
     AuthKey_XXXXXXXXXX.p8
   ```

2. 启动（Docker）：

   ```bash
   docker run -d --name movieclaw-push -p 8080:8080 \
     -v $PWD/config.yaml:/etc/movieclaw-push/config.yaml:ro \
     -v $PWD/AuthKey_XXXXXXXXXX.p8:/etc/movieclaw-push/AuthKey_XXXXXXXXXX.p8:ro \
     -v movieclaw-push-data:/data \
     ghcr.io/movieclaw/movieclaw-push:0.1
   ```

   镜像支持 amd64 和 arm64，版本见 [Releases](https://github.com/movieclaw/MovieClaw-Push/releases)；`0.1` 跟随 0.1.x 的修复版本，
   要固定版本就写完整的 `0.1.0`。也可以从源码构建：`docker build -t movieclaw-push .`。

   配置里 `data_dir` 写 `/data`，`apns.keys[].file` 写 `./AuthKey_XXXXXXXXXX.p8`（相对配置文件所在目录）。
   也可以直接用二进制：`go install github.com/movieclaw/movieclaw-push/cmd/movieclaw-push@latest`，然后 `movieclaw-push -config config.yaml`。

3. 前面放一个反向代理（Caddy、nginx……）终止 HTTPS。

4. 创建令牌，填进实例「设置 → 推送 → 自建中继」：

   ```bash
   docker exec movieclaw-push movieclaw-push token create --name 客厅服务器
   ```

## 自建中继的鉴权

自建中继**不需要** MovieClaw 官方授权，也不连接 MovieClaw 官方服务。要不要鉴权、用哪种方式，由你在 `auth.mode` 里决定：

| `auth.mode` | 实例怎么带凭证 | 适合 |
| --- | --- | --- |
| `static`（推荐） | 中继自己发的令牌 `mcpush_<ID>_<密钥>` | 绝大多数自建部署 |
| `none` | 不带凭证，只按设备做每日限流 | 只在内网能访问的中继 |
| `issuer` | 签发方签的 Ed25519 JWT（协议第 11、12 节） | 你自己运行了一个签发方 |

`static` 令牌的管理：

- `token create --name 名称` 创建，令牌**只显示一次**。中继在 `data_dir/tokens.json` 里只存它的 SHA-256，丢了只能吊销后重建。
- `token revoke <ID>` 吊销，运行中的中继一秒内生效，不用重启。
- 每个令牌单独计数、单独限额（`limits.day`）。一台机器一个令牌，哪台出问题就吊销哪个。

### 注意事项

1. **能推到哪个 App，由 .p8 决定，不由中继决定。** APNs 只接受 Bundle ID 所属开发者团队的密钥。自建中继只能推送你用自己的账号打包的 App。官方 App（`io.movieclaw.app`）的推送只能走官方中继，自建中继推不到它；反过来，官方中继也不推你的 Bundle ID（返回 `topic_not_allowed`）。
2. **公网上不要用 `none`。** 知道地址的人都能用你的 .p8 往你的 App 推送，只有按设备的每日上限（`limits.device_day`）挡着。
3. **`issuer` 模式不能直接信任 MovieClaw 官方 api。** 官方签发的令牌 `aud` 是官方中继，拉吊销名单还需要官方发给中继的专用密钥，自建中继拿不到。用 `issuer` 模式就得自己运行签发方。
4. **管理接口默认关闭。** 不配 `admin.key_file` 时 `/admin/v1/usage` 返回 404，查计数用命令行 `movieclaw-push usage`。要开就用足够长的随机串，它能读到所有实例的推送计数。
5. **HTTPS 交给反向代理。** 中继本身只说 HTTP，令牌是明文 Bearer，不经 HTTPS 暴露到公网等于公开令牌。`issuer` 模式下 `jwks`、`revocations` 也必须用 `https://`（中继不替你检查），否则公钥可能被中间人替换，任何人都能伪造令牌。
6. **保护好数据目录和 .p8。** `data_dir` 里有令牌哈希和计数，.p8 能以你的身份向你的 App 推送；权限给 `600`/`700`，不要放进代码仓库。
7. **限额先按默认值。** 每个令牌每天 5000 条、每台设备每天 500 条，覆盖正常使用绰绰有余；改成负数就是不限，出了问题没有兜底。

## 命令

```
movieclaw-push [-config config.yaml] [命令]

serve                      启动中继（默认）
token create --name 名称   创建静态令牌（auth.mode: static），令牌只显示一次
token list                 列出静态令牌
token revoke <ID>          吊销静态令牌（运行中的中继一秒内生效）
usage [--days 7]           查看按「实例 × 天」汇总的推送计数
version                    显示版本
```

配置文件路径也可以用环境变量 `MOVIECLAW_PUSH_CONFIG` 指定。

## 配置

两份完整示例：[examples/config.yaml](examples/config.yaml)（自建，`static` 鉴权）、[examples/config.official.yaml](examples/config.official.yaml)（官方，`issuer` 鉴权）。

| 配置 | 说明 |
| --- | --- |
| `listen` | 监听地址，默认 `:8080` |
| `aud` | 中继的固定标识，issuer 模式下实例令牌的 `aud` 必须等于它 |
| `data_dir` | 计数文件、令牌文件、鉴权缓存的目录，默认配置文件旁的 `data/` |
| `apns.keys` | .p8 密钥（`team_id`、`key_id`、`file`），可以挂多把，第一把优先、被拒绝时自动换下一把 |
| `apns.topics` | 能推送的基础 Bundle ID |
| `apns.types` | 开放的推送类型，默认 `[alert]`；规则见协议第 6 节 |
| `apns.rules` | 追加或覆盖推送类型规则（高级） |
| `apns.alert_title` / `alert_body` | 中继替实例填的通用文案，默认「MovieClaw」「你有一条新通知」 |
| `apns.dry_run` | 不连接苹果，直接返回成功并记日志（本地开发用） |
| `auth.mode` | `issuer`、`static` 或 `none` |
| `auth.issuers` | issuer 模式：受信任的签发方（`iss`、`jwks`、`revocations`、`key_file`） |
| `auth.cache_dir` / `refresh_interval` | 公钥和吊销名单的落盘目录 / 拉取间隔（默认 5 分钟） |
| `limits` | 默认限额：`day`（每个实例每天，默认 5000）、`device_day`（每台设备每天，默认 500），负数不限 |
| `admin.key_file` | `/admin/v1/usage` 的管理密钥，不配则关闭该接口 |
| `log.level` | `debug`、`info`、`warn`、`error` |

## 开发

```bash
go test ./...                                          # 单元测试
go test ./internal/auth -run TestVectors -update       # 重新生成令牌测试向量
```

| 目录 | 内容 |
| --- | --- |
| `cmd/movieclaw-push` | 程序入口和管理命令 |
| `protocol` | 协议里可以直接执行的部分：消息格式、逐条检查、推送类型规则表、aps 允许清单、结果码（公开的 Go 包） |
| `apns` | 标准库 HTTP/2 写的 APNs 客户端（公开的 Go 包） |
| `internal/auth` | issuer / static / none 三种鉴权 |
| `internal/limit` | 限额与计数（SQLite、HyperLogLog） |
| `internal/server` | HTTP 接口：鉴权 → 按协议检查 → 限额 → 发给苹果 |
| `docs/protocol.md` | 推送中继协议 |
| `testvectors` | 实例令牌测试向量（公开的 Go 包），签发方用它核对自己的实现 |
