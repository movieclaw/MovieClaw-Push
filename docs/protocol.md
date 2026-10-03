# MovieClaw 推送中继协议 v1

本文是推送中继和调用方（MovieClaw 实例）之间的协议。本仓库的 `movieclaw-push` 是给自建用户的一份实现，MovieClaw 官方中继是另一份；两份都调用本仓库的 `protocol` 包执行协议，并跑通 `protocol/protocoltest` 一致性测试（第 12 节），实例连哪个中继都一样工作。

鉴权、限额怎么定、计数存在哪，是各个中继自己的事；协议只规定实例看得到的行为。

## 1. 中继做什么、不做什么

推送中继只做一件事：把认领过的实例发来的推送转发给 APNs。

- **看不到内容**：推送内容由实例端到端加密，中继只转发密文。中继能看到的字段只有控制类的数值或不透明值（优先级、角标、过期时间……），任何能看出语义的文字（事件类型、片名、通知分组名……）都不允许出现在明文里。
- **不知道手机属于谁**：设备令牌只在请求里出现，中继不保存；日志只记令牌哈希的前缀。
- **不认设备类型**：中继只认推送类型（alert、background……），iPhone、Apple TV 的差异由 App 和实例处理。
- **只记数字**：按「实例 × 天」汇总推送条数，用来执行限额；不记设备令牌，也不记内容。
- **不相信调用方声称的任何东西**：只检查自己能验证的（令牌签名、白名单、类型规则、限额），内容是否属实交给手机验证（带认证的加密）。

## 2. 接口一览

| 接口 | 鉴权 | 作用 |
| --- | --- | --- |
| `GET /v1/info` | 可选 | 协议版本、`aud`、能推送的 Bundle ID、开放的推送类型及规则、鉴权方式、默认限额；带上凭证时还有调用方的剩余额度 |
| `POST /v1/push` | `Authorization: Bearer <实例凭证>` | 批量推送，一次最多 100 条，每条单独返回结果 |
| `GET /healthz` | 无 | 健康检查 |

所有请求和响应都是 JSON（UTF-8）。整个请求的错误用 HTTP 状态码表示，响应体是：

```json
{"error": "unauthorized", "message": "实例凭证无效或已过期"}
```

| 状态码 | `error` | 含义 |
| --- | --- | --- |
| 400 | `bad_request` | 请求体不是合法的 JSON，或 `messages` 为空 |
| 400 | `too_many_messages` | 一次超过 100 条 |
| 401 | `unauthorized` | 缺少凭证、凭证无效、过期或已吊销 |
| 403 | `forbidden` | 凭证有效但没有 `push` 权限 |
| 503 | `unavailable` | 中继暂时没法核实凭证（比如它依赖的服务连不上），稍后重试 |

单条推送的问题（格式、类型、限额、苹果的拒绝……）不影响同批的其他推送，放在 200 响应的单条结果里。

## 3. 鉴权

凭证放在 `Authorization: Bearer <凭证>`，格式由中继决定，实例当作不透明的字符串原样带上。`/v1/info` 的 `auth.mode` 说明中继用哪种方式，实例用它决定带不带凭证、在设置页显示什么：

| `auth.mode` | 凭证 | 用在哪 |
| --- | --- | --- |
| `static` | 中继自己发的令牌 `mcpush_<ID>_<密钥>`（`movieclaw-push token create --name 名称`） | 自签 App 用户自建的中继（本实现） |
| `none` | 不带 `Authorization` | 只在内网，或运营方停运时的退路：任何人都能调用，只按设备限流（本实现） |
| `issuer` | 实例从 MovieClaw 云端拿到的 `access_token` | MovieClaw 官方中继 |

以后有别的值也只是名字不同：实例遇到不认识的 `auth.mode` 照样带上配置的凭证。

**实例必须支持 `none`**：`/v1/info` 声明 `auth.mode: none` 时不带凭证直接推送。否则运营方停运、把中继切到 `none` 时，老版本实例都切不过去。

## 4. `GET /v1/info`

```json
{
  "protocol": 1,
  "software": "movieclaw-push/1.0.0",
  "aud": "https://push.example.com",
  "platforms": ["apns"],
  "environments": ["production", "development"],
  "topics": ["io.movieclaw.app"],
  "types": {
    "alert": {
      "priorities": [10, 5, 1],
      "payload": "optional",
      "aps": {
        "badge": {"kind": "uint"},
        "sound": {"kind": "enum", "values": ["default"]},
        "interruption-level": {"kind": "enum", "values": ["passive", "active", "time-sensitive"]},
        "relevance-score": {"kind": "range", "min": 0, "max": 1}
      }
    }
  },
  "auth": {"mode": "static"},
  "limits": {"day": 5000, "device_day": 500},
  "max_batch": 100,
  "max_payload_bytes": 4096
}
```

| 字段 | 说明 |
| --- | --- |
| `protocol` | 协议主版本。只有破坏兼容时才升 |
| `aud` | 中继的固定标识，不随实例实际访问的地址变化（主备地址共用一个值） |
| `platforms` | v1 只有 `apns`；以后加安卓只多一个 `fcm` |
| `topics` | 能推送的基础 Bundle ID。实例按设备上报的 Bundle ID 匹配能推送它的中继 |
| `types` | **开放的**推送类型及各自的规则（第 6 节）。没列出的类型会被拒绝 |
| `auth` | 鉴权方式（第 3 节） |
| `limits` | 默认限额，键和第 9 节的限制名一致；负数表示不限。只用于展示，实际额度以每次推送响应里的 `quota` 为准 |
| `max_batch` / `max_payload_bytes` | 一次最多几条 / 最终发给苹果的 JSON 上限 |
| `quota` | 只在请求带了有效凭证时出现：调用方当前的剩余额度，格式和推送响应里的一样（第 5.4 节）；`none` 模式或不限额时没有 |

实例用新的推送类型前，先查 `types` 里有没有。

### 4.1 带上凭证

`/v1/info` 可以带 `Authorization: Bearer <实例凭证>`，规则和推送一样（第 3 节）。凭证有效时响应里多一个 `quota`，实例不发推送也能知道今天还剩多少额度，还能顺便确认中继连得通、凭证仍然有效。

带凭证不会让这个接口失败：凭证无效、已吊销，或中继暂时核实不了时，照常返回 200 和其余字段，只是没有 `quota`。实例在拿到凭证之前、或凭证已经过期时，也要能读到鉴权方式和开放的类型。

中继可以把带了有效凭证的请求记作这台实例的一次连接（比如在管理页面显示「最近一次连接」）。实例定期检查连通性时，建议带上凭证调这个接口，不要用空推送代替。

## 5. `POST /v1/push`

### 5.1 请求

```http
POST /v1/push
Authorization: Bearer <实例凭证>
Content-Type: application/json

{"messages": [<推送消息>, ...]}
```

请求体最大 1MB，`messages` 1–100 条。

### 5.2 推送消息（v1，定下后不再改）

```json
{
  "id": "6f1c2a9e-3b7d-4c55-9a10-2e8f4d6b7c01",
  "platform": "apns",
  "token": "a1b2c3d4…",
  "topic": "io.movieclaw.app",
  "environment": "production",
  "type": "alert",
  "priority": 10,
  "expires_at": 1767225600,
  "collapse_id": "k7Qm2xP9",
  "aps": {"interruption-level": "time-sensitive", "badge": 3},
  "payload": "v1.<key_id>.<nonce>.<密文>"
}
```

| 字段 | 必填 | 规则 |
| --- | --- | --- |
| `id` | 是 | 实例生成的随机 UUID。中继原样作为 `apns-id` 交给苹果，并写进日志和结果，实例日志、中继日志、苹果的返回三方能对上 |
| `platform` | 是 | v1 只有 `apns` |
| `token` | 是 | 设备令牌，十六进制字符串（32–400 个字符），大小写不敏感 |
| `topic` | 是 | **只填基础 Bundle ID**，后缀由中继按 `type` 补上，必须在 `/v1/info` 的 `topics` 里 |
| `environment` | 是 | `production` 或 `development`（Xcode 直接安装的调试版是 development，TestFlight 和 App Store 是 production） |
| `type` | 是 | 推送类型，见第 6 节 |
| `priority` | 否 | 对应 `apns-priority`，必须在该类型允许的优先级里；不填用该类型的默认值 |
| `expires_at` | 否 | 对应 `apns-expiration`，Unix 秒；`0` 表示苹果只尝试投递一次；不填由苹果决定 |
| `collapse_id` | 否 | 对应 `apns-collapse-id`。必须是不透明值：只能有字母、数字、`_`、`-`，最长 64；实例用本地密钥对「事件对象」做 HMAC 后截短，不能直接写订阅 ID 之类的值 |
| `aps` | 否 | 只允许该类型规则里列出的控制类字段，见第 7 节 |
| `payload` | 否 | 实例加密好的密文，中继不解析，只检查它只由 base64url 字符和点组成。可以不带（比如只改角标）；有的类型不能带 |

不认识的字段一律忽略。

### 5.3 中继的处理顺序

对每条消息依次检查，第一个不通过的检查决定结果：

1. 能解析成上面的结构 → 否则 `invalid_message`
2. `id` 是 UUID → `invalid_message`
3. `platform` 是 `apns` → `invalid_message`
4. `token` 是十六进制 → `bad_token`
5. `topic` 在白名单 → `topic_not_allowed`
6. `environment` 合法、`expires_at` 非负、`collapse_id` 是不透明值 → `invalid_message`
7. `type` 已开放 → `unsupported_type`
8. 优先级、`payload`、`aps` 符合该类型规则 → `invalid_message` / `invalid_aps`
9. 最终 JSON 不超过 4096 字节 → `payload_too_large`
10. 没超出限额 → `rate_limited`（通过的计入当天计数）
11. 发给苹果，按苹果的回应给出结果

### 5.4 响应

```json
{
  "results": [
    {"id": "6f1c2a9e-…-7c01", "result": "ok"},
    {"id": "6f1c2a9e-…-7c02", "result": "unregistered", "reason": "Unregistered",
     "unregistered_at": 1767225600000, "message": "设备令牌已失效（App 被卸载或关闭了通知），请删除这台设备的推送令牌"},
    {"id": "6f1c2a9e-…-7c03", "result": "rate_limited", "reason": "day", "limit": "day", "retry_after": 41023,
     "message": "这台实例今天的推送已达上限（5000 条），将在 UTC 零点（北京时间 8:00）恢复"}
  ],
  "quota": {"day": {"limit": 5000, "used": 4210, "remaining": 790, "reset_at": 1767312000}}
}
```

`results` 和请求的 `messages` 一一对应、顺序相同，并带回 `id`。

| 字段 | 说明 |
| --- | --- |
| `result` | 结果码，见下表 |
| `reason` | 出问题的字段名、触发的限制名，或苹果给的原因（如 `BadDeviceToken`） |
| `message` | 给人看的中文说明。实例原样显示在设置页即可，新的结果码、新的限制类型老实例也能看懂 |
| `retryable` | 只在 `apns_error` 时有意义：`true` 表示可以稍后重试 |
| `limit`、`retry_after` | 只在 `rate_limited` 时出现：触发的限制名、多少秒后恢复 |
| `unregistered_at` | 只在 `unregistered` 时出现：苹果给的令牌失效时间（Unix 毫秒） |

`quota` 是该实例的剩余额度（`none` 模式或不限额时没有）。实例快到上限时可以主动取舍：优先发 `alert`，静默推送和实时活动可以丢。

### 5.5 结果码

| 结果 | 含义 | 实例怎么做 |
| --- | --- | --- |
| `ok` | 苹果已接收 | — |
| `unregistered` | APNs 返回 410 | 删除这台设备的推送令牌 |
| `bad_token` | APNs 返回 400 BadDeviceToken，或令牌格式不对；可能只是令牌和环境不匹配 | 只标记、不删除，在设置页显示 |
| `rate_limited` | 超出限额 | 不在 `retry_after` 之前重试；把 `message` 原样显示在设置页 |
| `unsupported_type` | 中继没开放这种类型 | 可以退回 `alert` |
| `topic_not_allowed` | Bundle ID 不在白名单 | 提示改用自建中继 |
| `payload_too_large` | 最终发给苹果的 JSON 超过 4KB | 记日志 |
| `invalid_aps` | `aps` 里有不允许的字段或取值 | 记日志 |
| `invalid_message` | 消息格式不对（`id`、`platform`、`environment`、`priority`、`payload`、`collapse_id`……） | 记日志 |
| `apns_error` | 苹果返回的其他错误（或连不上苹果），带 `reason` 和 `retryable` | 按 `retryable` 处理 |

**实例遇到不认识的结果码时按失败处理、不重试，显示 `message`**——以后加结果码不算破坏兼容。

## 6. 推送类型

APNs 共有 12 种推送类型，每种的 topic 后缀、优先级规则、负载字段都不同。中继把规则写成一张表（内置于 `protocol/defaults.yaml`，配置里的 `apns.rules` 可以追加或整行覆盖），开放哪些类型由配置的 `apns.types` 决定。新类型加一行配置即可，不改协议。

| 类型 | 用途 | topic 后缀 | 优先级（首个为默认） | payload | 中继的处理 |
| --- | --- | --- | --- | --- | --- |
| `alert` | 弹出通知、角标、声音 | 无 | 10、5、1 | 可带 | 带 `payload` 时加通用文案（`apns.alert_title` / `alert_body`，默认「MovieClaw」「你有一条新通知」）和 `mutable-content: 1`，通知扩展解密后替换；不带 `payload` 时只转发角标等控制字段 |
| `background` | 静默推送，后台刷新数据 | 无 | 5 | 可带 | 强制 `content-available: 1`，不加任何文案。系统会限制频率，不保证马上送达 |
| `liveactivity` | 锁屏和灵动岛上的实时活动 | `.push-type.liveactivity` | 10、5 | 不能带 | `content-state`、`attributes` 只能是 `{"e": "<密文>"}`；`attributes-type` 只能是配置的不带语义的类型名（默认 `SealedActivityAttributes`）；要带提醒时写 `"alert": true`，中继替换成通用文案。tvOS 不支持 |
| `widgets` | 刷新桌面小组件 | `.push-type.widgets` | 5、10 | 不能带 | 强制 `content-changed: true`，只触发刷新、不带内容 |

`controls`、`complication`、`voip`、`pushtotalk`、`location`、`mdm`、`fileprovider`、`accessory` 不支持（非通话 App 用 voip 会被审核拒绝）。苹果的「广播推送」（按频道一对多）要用另一套频道管理接口，不适合按令牌推送的模型，不考虑。

### 规则表的格式

```yaml
- type: liveactivity                 # 类型名，同时是 apns-push-type 的取值
  topic_suffix: .push-type.liveactivity
  priorities: [10, 5]                # 允许的优先级，第一个是默认值
  payload: forbidden                 # optional | forbidden
  generic_alert: false               # 带 payload 时加通用文案和 mutable-content
  force: {}                          # 强制加进 aps 的字段，覆盖实例填的
  fields:                            # 实例可以填写的 aps 字段，不在这里的一律拒绝
    timestamp: {kind: timestamp, required: true}
    event: {kind: enum, values: [start, update, end], required: true}
    content-state: {kind: sealed}
```

| `kind` | 取值规则 |
| --- | --- |
| `uint` | 非负整数（JSON 数字，`"3"` 这样的字符串不算） |
| `timestamp` | 正整数，Unix 秒 |
| `range` | 数字，介于 `min` 和 `max` 之间 |
| `enum` | 字符串，只能是 `values` 之一 |
| `sealed` | 只能是 `{"e": "<密文>"}` |
| `const` | 只能等于配置的 `apns.attributes_type` |
| `generic_alert` | 只能是 `true`，中继替换成 `{"title", "body", "sound": "default"}` 通用文案 |

## 7. `aps` 允许清单（v1）

| 字段 | 取值规则 | 可用的类型 |
| --- | --- | --- |
| `badge` | 非负整数 | alert |
| `sound` | 只能是 `default`；不同事件用不同声音时，由通知扩展解密后设置 | alert |
| `interruption-level` | `passive`、`active`、`time-sensitive` | alert |
| `relevance-score` | 0 到 1 的数 | alert、liveactivity |
| `timestamp`、`event`、`stale-date`、`dismissal-date`、`content-state`、`attributes-type`、`attributes`、`alert`（`true`） | 见第 6 节 | liveactivity |

`thread-id`、`category`、`target-content-id`、`filter-criteria` 和 `alert` 下的任何文字都不允许出现在明文里。分组和操作按钮由通知扩展解密后设置（`thread-id`、`category` 放进密文）。值为 `null` 的字段视为不合规。

## 8. 最终发给苹果的内容

```http
POST https://api.push.apple.com/3/device/<token>
apns-id: <消息的 id>
apns-topic: <topic + 类型后缀>
apns-push-type: <type>
apns-priority: <priority>
apns-expiration: <expires_at>         （填了才有）
apns-collapse-id: <collapse_id>       （填了才有）
authorization: bearer <provider 令牌>

{"aps": {"alert": {"title": "MovieClaw", "body": "你有一条新通知"}, "badge": 3,
         "interruption-level": "time-sensitive", "mutable-content": 1},
 "e": "v1.<key_id>.<nonce>.<密文>"}
```

- 密文放在顶层的 `e` 字段，通知扩展从 `userInfo["e"]` 读取。
- `environment` 为 `development` 时发往 `api.sandbox.push.apple.com`。
- 中继和苹果的正式、测试环境各保持一条 HTTP/2 长连接；provider 令牌（ES256）每 50 分钟刷新一次（苹果要求 20–60 分钟）。
- 可以挂多把 .p8：第一把优先，苹果返回 `InvalidProviderToken` 时自动换下一把并暂停用旧的 10 分钟。换密钥时先加新密钥，再去苹果后台吊销旧的，推送不中断。

## 9. 限额与计数

限额多少、按什么维度由中继决定，实例只需要处理 `rate_limited`、显示 `message`、参考 `quota`。共同的规则：

- 日界按 UTC 划分，限额在 UTC 零点（北京时间 8:00）重置。
- 通过限额检查、准备发给苹果的推送计入当天条数（苹果后来拒绝的也算）。
- 负数表示不限；`0` 表示一条都不能发。
- 中继以后加新的限制（按推送类型、按优先级……）只是多一个限制名，实例不用升级。

本实现的两个限制，都在配置的 `limits` 里：

- `day`：每个令牌每天（默认 5000）。`none` 模式不检查。
- `device_day`：每台设备每天（默认 500），按设备令牌的哈希计数、覆盖所有令牌，只放内存，中继重启清零。

按「实例 × 天」的汇总（条数、各类型和优先级的条数、近似的不同设备数、每小时条数、失败原因）写进 `data_dir` 下的 SQLite，每 10 秒写一次，保留 7 天，用 `movieclaw-push usage` 查看。不同设备数用 HyperLogLog 近似计数（误差约 3%），不保存设备令牌或令牌哈希。

## 10. 向前兼容

- 中继忽略消息里不认识的字段；不支持的类型在单条结果里报错，不影响同批的其他推送。
- 实例用新类型前先查 `/v1/info`；遇到不认识的结果码按失败处理并显示 `message`。
- 只有破坏兼容时才升协议版本（`protocol` 和路径里的 `v1`）。加类型、加字段、加结果码、加限额都不算。

## 11. 日志

中继的日志只记：实例标识、追踪 `id`、设备令牌哈希的前 8 个十六进制字符、结果（和原因）。不记推送内容、不记完整令牌。官方部署保留 30 天。

## 12. 一致性测试

`protocol/protocoltest` 是这份协议的一致性测试，以 Go 包发布：`protocoltest.NewAPNs` 起一个假的 APNs，`protocoltest.Run` 只通过 HTTP 调用被测中继，再到假 APNs 上核对苹果实际收到了什么。覆盖 `/v1/info` 的格式（包括带凭证时的 `quota`）、鉴权失败、整批出错、第 5.3 节的每一步检查、第 8 节发给苹果的请求头和内容、苹果各种回应对应的结果码、`rate_limited` 和 `quota` 的格式。

任何中继实现都应该跑通它。改协议时先改这份文档和一致性测试，再改实现。本实现的测试编译真实的程序对它跑：`go test ./cmd/movieclaw-push -run TestConformance`。
