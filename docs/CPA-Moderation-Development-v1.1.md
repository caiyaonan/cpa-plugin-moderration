# CPA Moderation 插件 — Agent 开发规格 v1.1

版本：v1.1 | 2026-11-25 | 目标：CLIProxyAPI v8.1.2（commit `85225381d89915595598ed13766cd79890c03a84`）、NewAPI、Docker Compose、Linux amd64

> v1.1 相对 v1.0 的变化：
> 1. 以实际读过的 CPA v8.1.2 源码和参考插件 `cpa-plugin-key-billing` v1.5.4（commit `0dcca96`）为准，把第 2 节的“待调查”大部分改成“已确认”，剩余的列为 PoC 待验证项。
> 2. 产品语义改为：**只审核“指定 Key × 指定模型”的请求**，其他请求直接放行（去掉 v1.0 里的全局 baseline 强制审核）。
> 3. 管理页面、Key 同步、存储、构建方式照搬 key-billing 的已验证做法。
> 4. 新增宿主 **fail-open（失败放行）** 风险和对策，这是本插件最关键的安全约束。

---

## 1. 任务

实现 CPA 原生插件 `cpa-moderation`（c-shared 动态库）。管理员在页面上建立“审核规则”，规则包含模型列表和审核选项，再把 CPA 下游 API Key 绑定到规则。请求的 Key 已绑定、且模型命中规则时，插件在 CPA 选择上游凭证之前，把请求里的文本和图片发给 OpenAI `omni-moderation-latest`（加上本地词库）检查，违规就直接拒绝，请求不会到达上游。

不修改 CPA 主程序，不改写用户的 prompt，不绕过上游安全机制。审核能降低风险，但不能保证上游账号不被限制。

## 2. 宿主契约（已在 v8.1.2 源码中确认）

| 项 | 结论 | 证据 |
|---|---|---|
| 插件形态 | CGO `-buildmode=c-shared`，导出 `cliproxy_plugin_init(host*, api*)`，**不是** Go `plugin.Open` | key-billing `cmd/cpa-key-billing/main.go` |
| 调用协议 | 宿主调用 `api.call(method, json)`，返回 `{"ok":bool,"result"|"error"}` 信封；插件通过 `host.call` 回调宿主 | 同上，`internal/plugin/envelope.go` |
| ABI / schema | `abi_version=1`；registration 中 `schema_version` 参考 key-billing 用 7（以 `sdk/pluginabi/types.go` 注释为准） | `sdk/pluginabi/types.go` |
| 加载配置 | CPA `config.yaml` 的 `plugins.configs.<plugin-id>`，以 `config_yaml` 字节传入 `plugin.register` / `plugin.reconfigure` | key-billing README、`app.go` |
| 拦截点 | `request.intercept_before`：在**凭证选择之前**调用，可拿到 `Body`（不能声明 `request_interceptor_omit_body_before`）、`Model`、`RequestedModel`、`SourceFormat`、`Stream`、`CallerScope`、`Metadata` | `sdk/pluginapi/types.go:1448`、`sdk/api/handlers/handlers_interceptors.go:515` |
| 拒绝方式 | 返回 `Terminate:true` + `StatusCode` + `ResponseHeaders` + `ResponseBody`，请求不会到达上游执行器 | `types.go:1475`、`handlers_interceptors.go:545` |
| 身份 | `caller_scope` = hex(sha256(`"cli-proxy-api:caller-scope:v1\x00"` + apiKey))，不可逆 | key-billing `billing/identity.go` |
| Key 列表 | 插件拿不到明文 Key：管理页前端用管理密码调用 CPA `GET /v0/management/api-keys`，再 POST 到插件 `/keys/sync`，插件只保存 scope 和打码预览 | key-billing `web/data.js:400,490`、`admin.go:271` |
| 管理 API / 页面 | `management.register` 返回路由；API 前缀 `/v0/management/plugins/<id>/...`（继承 CPA 管理鉴权），页面挂在 `/v0/resource/plugins/<id>/ui`，CPAMC/CPAMP 侧边栏会显示菜单 | key-billing `management.go` |
| 模型列表 | `host.auth.models` 返回各凭证可服务的模型，可用于页面里的模型多选 | key-billing `host_auth.go` |
| 外部 HTTP | 可以在插件内直接使用 Go `net/http`，也可以用宿主的 `host.http.do` | key-billing `host_http.go` |
| 插件嵌套调用 | `Metadata.source == "plugin_host_model_callback"` 表示其他插件发起的内部调用 | key-billing `types.go` |

### 2.1 ⚠️ 宿主 fail-open 行为（必须处理）

`internal/pluginhost/adapters_interceptors.go:22-39`：
- 拦截器**返回 error** → 宿主只打 Warn 日志，**跳过本插件，请求照常发往上游**；
- 拦截器 **panic** → 宿主 `fusePlugin` **熔断本插件**，之后所有请求都跳过它，直到重启。

> **PoC 实测更正（见 `docs/compatibility.md` §5）**：返回 error 确认是 fail-open；但插件 **panic 会直接让整个 CPA 进程崩溃**，宿主的熔断机制根本兜不住（插件的 Go runtime 和宿主不是同一个）。所以 recover 不只关系到审核安全，也关系到 CPA 能不能活下来。

对策（硬性要求）：
1. `request.intercept_before` **永远不返回 error**。解析失败、审核超时、配置损坏、内部异常，一律转成 `Terminate` 拒绝响应（400/413/503）。
2. 每个方法入口都用 `recover()` 兜底，panic 同样转成 503 拒绝，绝不能让 panic 穿过 C ABI。
3. 插件状态异常（例如配置加载失败）时，对命中规则的 Key 一律 503，不能退化成放行。
4. 文档和页面上要明确写出：**插件被禁用、卸载、或宿主熔断时，审核失效**。运维需要监控 CPA 日志里的 `pluginhost: request interceptor cpa-moderation failed` 和 fuse 关键字。

### 2.2 PoC 验证项（结果详见 `docs/compatibility.md`）

- [x] 最小插件能被 v8.1.2 加载（Windows DLL 已验证；注册时 Name/Version/Author/GitHubRepository 都不能为空）。
- [x] 认证失败的请求不会进入拦截器（401，插件未被调用）。
- [x] 各路由 Body 都是**客户端原始请求**：chat、responses、claude、gemini 是原始 JSON；`/v1/images/edits` 是**原始 multipart 字节**（boundary 在 `Headers["Content-Type"]` 里），插件需要自己解析 multipart。
- [x] 重试时 `intercept_before` 只调用 1 次（`intercept_after` 每次重试都调用），所以在 before 阶段审核，每个请求只审一次。
- [x] Terminate 后上游计数为 0；流式请求被拒时返回普通 JSON；query 里的 `?key=` 和 Header 里的 key 得到相同的 `caller_scope`。
- [x] 别名：before 阶段的 `Model` 还是客户端请求的名字（别名尚未解析），规则按客户端模型名匹配。
- [ ] Codex WebSocket（`codex_websockets_duplex.go`）的每一轮输入是否都经过 `intercept_before`。
- [ ] 多插件共存时的调用顺序：前面的插件改写过的 Body 会传给后面的插件（`currentBase`）。审核插件的 `priority` 应保证在所有改写 Body 的插件**之后**运行，审核的是最终发往上游的内容。
- [ ] 拦截器调用有没有宿主侧超时；审核外呼最长耗时要小于客户端超时。
- [ ] `Terminate` 响应在流式请求下返回的是普通 JSON，Claude Code / Codex / OpenAI SDK 能正确报错，不会无限重试。

## 3. 产品语义（按需求调整）

**只有“已绑定规则的 Key” × “命中该规则的模型”才审核，其余全部放行。**

```
请求 → caller_scope 绑定了审核规则？ ─否→ 放行
                    │是
                    ▼
       模型（RequestedModel，回退 Model）命中规则的模型列表？ ─否→ 放行
                    │是
                    ▼
       接口在规则覆盖范围内？ ─否（不支持的接口）→ 按规则配置：拒绝(默认) / 放行
                    │是
                    ▼
       提取文本+图片 → 本地词库 → 命中则 403
                    │未命中
                    ▼
       OpenAI Moderation → flagged 则 403；失败按 on_error（默认 503）
                    │通过
                    ▼
                  放行
```

- 一个 Key 可以绑定多条规则；多条命中时取并集（检查项取最严，`on_error` 取 deny）。
- 模型匹配支持精确值和 `*`、`?` 通配符，区分大小写。**同时检查 `RequestedModel` 和 `Model`，任一命中即审核**。PoC 表明 before 阶段两者都是客户端使用的名字（别名还没解析），所以规则里应该填客户端可见的模型名，**包括别名**。管理页的模型列表应该同时列出别名。按上游真实模型匹配的做法见 compatibility.md §4（P1）。
- `Metadata.source == plugin_host_model_callback` 的内部调用：沿用发起请求的 scope；不确定时按命中处理（宁可多审）。
- 页面上要明确说明：未绑定的 Key 不做任何审核。这是有意为之的设计。

## 4. 配置分层

### 4.1 静态配置（CPA config.yaml，重启或 reconfigure 生效）

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    cpa-moderation:
      enabled: true
      priority: 10                       # 低于会改写 Body 的插件，见 2.2
      state_file: "plugins/cpa-moderation-state-v1.db"
      openai:
        base_url: "https://api.openai.com/v1"
        api_key_env: "OPENAI_MODERATION_API_KEY"   # 只从环境变量读取，不写进配置和页面
        model: "omni-moderation-latest"
        proxy_url: ""                    # 可选，访问 OpenAI 的出口代理
        timeout_ms: 8000
        max_inflight: 16
        rpm_limit: 0                     # 0 = 不在本地限流，按账号实际额度配置
      limits:
        max_body_bytes: 33554432
        max_text_bytes: 262144
        max_images: 8
        max_image_bytes: 10485760
      audit_retention_days: 14
      debug: false
```

### 4.2 动态配置（管理页面编辑，存入 state_file，即时生效）

```jsonc
// 审核规则
{
  "id": "image-business",
  "name": "生图业务",
  "enabled": true,
  "models": ["gpt-image-*", "gpt-6*"],
  "endpoints": [],                 // 空 = 所有已支持的接口
  "check_text": true,
  "check_image": true,
  "include_roles": ["system","user","tool"],   // 是否审 assistant 历史，默认不审
  "history_mode": "all",           // all | last_n（配合 history_last_n）
  "category_actions": {},          // 可选：某类别只记录不拦截，例如 {"violence":"log"}
  "rule_sets": ["business-words"],
  "unsupported_content": "deny",   // 文件/音频/无法解析的引用：deny | allow
  "on_error": "deny"               // 审核服务不可用：deny(503) | allow
}
// Key 绑定：scope → [rule_id...]（与 key-billing 的 keys/routes 同构）
// 词库：id、name、keywords[]、regex[]、action(block/log)
```

并发写入用 revision 号，冲突返回 409。写入失败时保留上一份有效配置；运行时用原子替换的不可变快照，审核请求不持锁。

## 5. 管理页面（参照 key-billing）

挂载在 `/v0/resource/plugins/cpa-moderation/ui`，单文件 HTML（`ui.html` 加内联 css/js，`go:embed`），CSP 与 key-billing 保持一致，中英文 i18n。

| 页签 | 功能 |
|---|---|
| API Key | 从 CPA 同步 Key 列表（显示打码预览和备注），多选 Key 后绑定或解绑审核规则；显示每个 Key 当前生效的规则 |
| 审核规则 | 新建/编辑/启停规则；模型多选（数据来自 `host.auth.models`，支持手填通配符），实时预览“会命中哪些模型”；检查项、角色范围、类别动作、on_error |
| 词库 | 编辑关键词和正则，导入导出（txt/JSON），正则保存前用 RE2 校验 |
| 模拟测试 | 选择 Key、模型，粘贴请求体 → 显示命中的规则、提取出的内容摘要（条数/字节数，不回显全文）和审核结论；**不转发生成请求** |
| 审核日志 | 时间、Key 预览、模型、接口、规则 ID、结论（通过/拦截/错误）、类别、耗时、缓存命中；分页、时间筛选、清空 |
| 状态 | OpenAI Key 是否已配置、连通性测试（发送固定无害文本）、近 24h 请求量/拦截率/错误率/P95、插件版本 |

建议的管理 API（前缀 `/v0/management/plugins/cpa-moderation`）：
`GET /keys`、`POST /keys/sync`、`PUT /keys/rules`、`GET|POST|PATCH|DELETE /rules`、`GET|PUT /wordlists`、`GET /models`、`POST /simulate`、`POST /provider/test`、`GET|DELETE /events`、`GET /status`。所有写接口使用严格 JSON 解码（`DisallowUnknownFields`）。

## 6. 内容提取覆盖矩阵

| SourceFormat / 路由 | 提取内容 | 状态 |
|---|---|---|
| openai `/v1/chat/completions` | messages[].content（字符串/数组中的 text、image_url），按 include_roles 过滤；tool 消息内容 | P0 |
| openai-response `/v1/responses`（含 Codex） | instructions、input（字符串/数组）、input_text、input_image、function_call_output | P0；`previous_response_id` 引用的历史拿不到，只审本次 input，并记录到已知限制 |
| `/v1/images/generations` | prompt | P0 |
| `/v1/images/edits` | prompt + 所有输入图片 | P0；PoC 确认收到的是原始 multipart，用 `mime/multipart` 按 Content-Type 中的 boundary 解析，限制 part 数量和大小 |
| claude `/v1/messages`（含 Claude Code） | system、messages[].content 的 text、image（base64）、tool_result 内容 | P0（CPA 的主要流量来源） |
| gemini `generateContent` | contents[].parts 的 text、inlineData；systemInstruction | P1 |
| `/v1/videos`、音频、input_file、远程文件 URL | 无法审核 | 按 `unsupported_content` 处理，默认拒绝（400） |

提取规则：
- 只读解析，**不修改 Body**（不返回 `Body`/`BodyEdits`）。
- 长度、数量、深度超出限制时返回 413，不能静默截断。超过单次 Moderation 输入上限的长文本分块审核（块之间保留重叠），任一块命中即拒绝。
- 远程 `http(s)` 图片 URL：默认不下载，直接把 URL 交给 Moderation API（由 OpenAI 去拉取），插件侧不存在 SSRF；可以配置为拒绝远程 URL。
- 本地匹配前做 NFKC 规范化和大小写折叠，只用于匹配，不影响请求内容。

## 7. 审核引擎

- **本地词库**：AC 自动机加 RE2 正则；命中只返回规则 ID，不回显敏感词。
- **OpenAI**：`POST {base_url}/moderations`，Bearer 使用独立 Key（不能用 CPA 的上游凭证，也不能通过 CPA 自己转发，否则会递归）。任一 result `flagged=true` 且对应类别动作为 block → 拒绝。`results` 为空或结构异常按错误处理。单次请求的图片数量、大小上限先查官方文档确认，超出就拆成多次调用。
- **缓存**：按单条消息/单张图片的 SHA-256（加上模型版本）缓存“通过”结果，TTL 10 分钟，LRU 上限。多轮对话里的历史消息命中缓存后，只审新增部分，可以大幅节省 RPM。不缓存拒绝结果，也不缓存错误；规则变更时清空缓存。
- **限流与并发**：semaphore 控制 `max_inflight`，队列有界；排不上队直接 503，不无限等待。尊重上游 429 的 Retry-After，默认不重试。
- 不使用后台 goroutine 或定时器（沿用 key-billing 的约束），所有工作都在宿主调用内同步完成；日志清理在写入时顺带执行。

## 8. 错误契约

按 `SourceFormat` 输出对应格式（参照 key-billing `refusals.go`：claude/anthropic 用 `{"type":"error","error":{...}}`，其余用 OpenAI 格式）。

| 场景 | HTTP | code |
|---|---|---|
| 内容违规（词库或 Moderation） | 403 | `content_policy_violation` |
| 正文无法解析、不支持的内容 | 400 | `moderation_input_invalid` |
| 超出大小或数量限制 | 413 | `moderation_input_too_large` |
| 审核服务不可用、超时、插件内部错误 | 503 | `moderation_unavailable` |
| 本地并发或队列已满 | 429 | `moderation_rate_limited` |

响应 message 中带 `request_id`，方便用户报给管理员；不包含原文、命中词、分数或密钥。

## 9. NewAPI 集成注意事项（必须写进运维文档）

- **自动禁用渠道**：NewAPI 会按状态码或关键词自动禁用渠道。必须确认 403 `content_policy_violation`、503 `moderation_unavailable` **不会**触发渠道禁用，必要时调整 NewAPI 的自动禁用配置。
- **重试**：NewAPI 失败后可能重试到其他渠道。如果其他渠道没经过本插件，就等于绕过审核。要求：同一业务的所有渠道都指向带插件的 CPA，或者对这类错误码关闭重试。
- **身份粒度**：多个 NewAPI 用户共用一个 CPA Key 时，只能做到渠道级审核。
- NewAPI 自带的敏感词过滤可以作为前置第一层，本插件作为第二层，两者不冲突。

## 10. 存储、日志与安全

- 状态存储：SQLite（`mattn/go-sqlite3`，插件本身就是 CGO 构建，与 key-billing 一致），保存规则、绑定、词库和审核日志。schema 版本化，迁移失败就回滚，不能删除数据。
- 日志字段：时间、request_id、scope 打码、模型、接口、规则 ID、结论、类别、耗时、缓存命中、错误类型。**禁止**保存明文 Key、Authorization、prompt 原文、图片、Base64。
- 管理接口继承 CPA 管理鉴权；OpenAI Key 只从环境变量读取，页面上只显示“已配置/未配置”。
- 审核内容会发送给 OpenAI，部署方需要确认隐私和数据处理是否合规。
- 已知或疑似 CSAM 不得提交给普通 Moderation API，测试中也不得使用真实违规素材。

## 11. 仓库结构（对齐 key-billing）

```text
cpa-moderation/
  cmd/cpa-moderation/main.go        # C ABI 胶水（//go:build cshared）
  cmd/cpa-moderation/main_stub.go   # 让普通 go test/vet 可用
  internal/plugin/                  # 方法分发、拦截、管理路由、UI 嵌入、refusal
  internal/plugin/web/              # ui.html + css/js + locales
  internal/policy/                  # 规则、绑定、匹配
  internal/extract/                 # 各 SourceFormat 的内容提取
  internal/rules/                   # AC 自动机 + RE2
  internal/moderation/              # OpenAI 客户端、限流、缓存
  internal/store/                   # SQLite
  scripts/e2e_cpa_moderation.sh     # 拉起真实 CPA v8.1.2 + 假上游 + 假审核端点
  docs/compatibility.md  docs/operations.md  docs/security.md
  install.sh  install.ps1
  .github/workflows/{check,release}.yml
```

构建：参照 key-billing `release.yml`。Linux 在 `manylinux2014` 容器中执行 `CGO_ENABLED=1 go build -tags cshared -buildmode=c-shared`（glibc 2.17 基线），产物命名为 `cpa-moderation-v<ver>.so`。CPA 官方 Docker 镜像的 libc 要先确认（如果是 musl/alpine，需要另外构建）。Go 版本与 CPA v8.1.2 的 `go.mod` 保持一致。

## 12. 测试矩阵（精简为必须项）

| ID | 场景 | 期望 |
|---|---|---|
| T01 | 已绑定 Key + 命中模型 + 正常内容 | 审核 1 次，上游 1 次 |
| T02 | 未绑定 Key，或模型不命中 | 不调用审核，直接放行 |
| T03 | 通配符、多规则、别名（RequestedModel ≠ Model） | 任一命中即审核 |
| T04 | 本地词库命中（合成测试词） | 403，上游 0 次 |
| T05 | mock flagged=true | 403，上游 0 次，没有凭证冷却或轮换 |
| T06 | mock 429/500/超时/空 results/坏 JSON | 503，上游 0 次 |
| T07 | **插件内部 panic、配置损坏** | 仍返回 503，**宿主没有熔断本插件**，上游 0 次 |
| T08 | chat / responses / messages 多轮、结构化内容、tool_result | 内容提取完整，Body 字节不变 |
| T09 | images generations / edits（multipart 与 JSON） | prompt 和每张图都审到 |
| T10 | 超限、非法 Base64、video/file | 413 / 400 |
| T11 | 流式请求被拒 | 返回 JSON 错误，各客户端正确显示 |
| T12 | 缓存：历史消息命中、规则变更后失效 | 不跨规则复用结果 |
| T13 | 管理页：同步 Key、并发编辑冲突、未登录访问 | 409 / 401 |
| T14 | 日志检查 | 没有原文和密钥 |
| T15 | 真实 CPA v8.1.2 Docker 加载、升级、回滚 | 管理面板可见，版本正确 |
| T16 | 通过 NewAPI 访问 | 403/503 正确透传，渠道没被禁用，没有重试到其他渠道 |

`go vet ./...`、`go test -race ./...`、`gofmt -l .`，以及 e2e 脚本全部通过后才能发布。mock 测试通过不能代替真实宿主加载测试。

## 13. 开发阶段

1. **PoC**（1–2 天）：最小 .so，打印 `intercept_before` 收到的各路由 Body 和元数据，完成 2.2 的全部勾选项。
2. **核心**：规则匹配、内容提取、词库、OpenAI 客户端、拒绝响应、fail-closed 兜底，以及单元测试。
3. **宿主集成**：e2e 脚本、各路由、NewAPI 联调。
4. **管理页面**：Key 同步与绑定、规则、词库、模拟、日志、状态。
5. **发布**：release workflow、安装脚本、运维文档（含 fail-open 风险说明）。

## 14. 参考

- CPA v8.1.2 源码：`sdk/pluginapi/types.go`、`sdk/pluginabi/types.go`、`sdk/api/handlers/handlers_interceptors.go`、`internal/pluginhost/adapters_interceptors.go`、`sdk/api/handlers/openai/openai_images_handlers.go`、`examples/plugin/`
- 参考插件：https://github.com/haowang02/cpa-plugin-key-billing （MIT；C ABI 胶水、管理页、Key 同步、refusal 格式）
- https://github.com/LTbinglingfeng/key-model-access
- OpenAI Moderation：https://developers.openai.com/api/docs/guides/moderation
