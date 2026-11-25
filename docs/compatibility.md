# CPA 宿主兼容性记录（PoC 结果）

日期：2026-11-25
宿主：CLIProxyAPI tag `v8.1.2`，commit `85225381d89915595598ed13766cd79890c03a84`，在 Windows amd64 上从源码构建（`GOTOOLCHAIN=go1.26.10 go build ./cmd/server`）
插件：`poc/probe`（c-shared DLL，CGO 编译器用的是 zig 0.17.1 `cc -target x86_64-windows-gnu`）
上游：`poc/mock_upstream.py`（假的 OpenAI 兼容 + Claude 上游）
复现：`poc/run` 目录下启动 mock 和 `cpa.exe -config config.yaml`，然后执行 `bash ../run_cases.sh`

> 运行在 Windows 上。Linux/Docker（官方镜像基于 debian:bookworm，glibc）的加载行为还需要在目标环境里再测一遍（T15）。

## 1. 加载与注册

| 项 | 结果 |
|---|---|
| 插件发现 | `plugins.dir` 下的 `<id>.dll`（Linux 为 `.so`）；插件 ID 就是文件名 |
| 宿主传入的 `schema_version` | 10 |
| 注册校验 | `Metadata.Name / Version / Author / GitHubRepository` **都不能为空**，否则报 `returned invalid metadata or no capabilities`，插件不生效（`internal/pluginhost/host.go:1459`） |
| `config_yaml` | 收到的是 `plugins.configs.<id>` 节点的原始 YAML（包含 `enabled`、`priority`） |
| register 调用次数 | 启动期间被调用了 5 次，`configure` 必须幂等 |
| CPA 回写配置 | 启动时 CPA 会把 `management.secret-key` 改写成 bcrypt 哈希，并写入 `server.server-id`。插件配置不受影响，但部署时要知道 config.yaml 会被宿主修改 |

## 2. `request.intercept_before` 实测

| 用例 | 路由 | SourceFormat | Body 形态 | 结果 |
|---|---|---|---|---|
| 01 | `/v1/chat/completions` | `openai` | 客户端原始 JSON（多轮 + data URL 图片完整） | ✅ |
| 02 | 同上，stream | `openai`，`Stream=true` | 原始 JSON | ✅ |
| 03 | 别名 `friendly-alias` → `mock-chat` | `openai` | before 阶段 `Model=RequestedModel=friendly-alias`；**只有 after 阶段 `Model` 才是 `mock-chat`** | ✅ 见 §4 |
| 04 | `/v1/responses` | `openai-response` | 原始 responses JSON（instructions、input_text、input_image）；上游实际收到的是 CPA 转换后的 chat JSON | ✅ |
| 05 | `/v1/images/generations` | `openai-image` | 原始 JSON | ✅（模型需要配置 `image: true`） |
| 06 | `/v1/images/edits` multipart，2 张图 | `openai-image` | **原始 multipart 字节**，`Headers["Content-Type"]` 带 boundary | ✅ 插件需要自己解析 multipart |
| 07 | `/v1/messages` stream（含 image、tool_use、tool_result） | `claude` | 原始 JSON | ✅ |
| 15 | 另一个 Key | `openai` | — | ✅ `caller_scope` 不同 |
| 16 | `/v1beta/models/x:generateContent?key=...` | `gemini` | 原始 JSON | ✅ query 里的 key 和 Header 里的 key 得到**相同的** `caller_scope`；`request_path` 是路由模式 `/v1beta/models/*action`，不是实际路径 |

Metadata 中稳定存在的键：`caller_scope`（64 位 hex）、`request_path`、`requested_model`、`request_id`、`trace_id`、`generate`、`service_tier`。`CallerScope` 字段与 `Metadata.caller_scope` 一致。

## 3. 拒绝、认证与重试

| 用例 | 结果 |
|---|---|
| 08 无效 Key | 401，插件**没有被调用** ✅ |
| 09/10/11/12 Body 带 `PROBE_BLOCK`（chat、chat stream、claude stream、images edits multipart） | 返回插件给的 403 和 Body，上游计数 **0**；流式请求返回的也是普通 JSON；`request.complete` 收到 `Outcome=rejected, StatusCode=403` ✅ |
| 13 上游 500，`request-retry: 2` | `intercept_before` **调用 1 次**，`intercept_after` 调用 3 次（每次重试一次），上游收到 3 次 → 审核放在 before，每个请求只需审一次 ✅ |
| 13（cooling 开启时） | 上游 500 会让凭证进入冷却，后续请求返回 503 `auth_unavailable`。这是宿主行为，与插件无关 |

## 4. 别名

before 阶段的 `Model` 是客户端请求的名字，还没有按别名解析。真实上游模型名只在 after 阶段才能拿到（`Model`），但 after 阶段在每次重试时都会调用。

结论：**策略匹配以 before 阶段的 `RequestedModel`/`Model`（即客户端看到的模型名）为准**。管理员在规则里写的应该是客户端使用的模型名（包括别名）。如果确实要按上游真实模型匹配，可以在 after 阶段补一次“只匹配、不重复审核”的检查（按 RequestID 复用 before 的审核结论）。这是 P1 项。

## 5. ⚠️ 失败语义（最重要）

| 用例 | 行为 | 影响 |
|---|---|---|
| 14 插件返回 error envelope | 宿主日志 `request interceptor cpa-mod-probe failed`，**请求照常发往上游，返回 200** | **fail-open**：任何未处理的错误都等于放行 |
| 99 插件内部 panic | **整个 CPA 进程崩溃退出**（`panic: probe panic requested ... goroutine 17 [running, locked to thread]`），之后所有请求都连不上 | 比 v1.1 文档里预计的“熔断插件”更严重：插件的 Go runtime 和宿主的 recover 不在同一个运行时里，宿主的 `fusePlugin` 兜不住 |

硬性要求（已写入开发规格）：
1. `cliproxyPluginCall` 入口第一行就要 `defer recover()`，把 panic 转成 `Terminate` 503 拒绝响应。只有这样才能既不让宿主崩溃，又不放行请求。
2. `request.intercept_before` 永远返回 `ok:true`，所有失败都编码成 `Terminate` 响应，绝不返回 error envelope。
3. 用 T07 测试覆盖这两点：注入 panic 和内部错误时，返回 503、上游 0 次、CPA 进程仍然存活。

## 6. 尚未覆盖（下一轮 PoC 或在集成阶段补）

- [ ] Linux `.so` 在官方 Docker 镜像中的加载（glibc 基线 2.17 的 manylinux 构建）
- [ ] Codex WebSocket（`codex_websockets_duplex.go`）每一轮输入是否都经过 `intercept_before`
- [ ] 多插件共存时的执行顺序（`priority`）以及前一个插件改写 Body 后的可见性
- [ ] 拦截器长时间阻塞（模拟审核耗时 5–10s）时，宿主有没有超时，客户端会不会断开
- [ ] 真实客户端（Claude Code、Codex CLI、OpenAI SDK）收到 403/503 后的显示和重试行为
- [ ] NewAPI → CPA 链路的状态码透传、自动禁用渠道和重试行为
- [ ] Claude 原生格式的错误体（PoC 统一返回的是 OpenAI 格式；正式实现按 `SourceFormat` 区分）

## 7. 与其他插件共存：cpa-key-billing（2026-11-25 实测）

环境：同一个 CLIProxyAPI v8.1.2（Windows）同时加载 `cpa-moderation` 0.1.0 和 `cpa-key-billing` 1.5.4（从源码 commit `0dcca96` 编译）。key-billing 配置了 `allow_unpriced_models: true`，K1 的并发上限设为 1。脚本：`poc/combo/run_combo.sh <billing-first|moderation-first>`。

执行顺序由 `priority` 决定，数值大的先执行，相同时按插件 ID 排序（`internal/pluginhost/snapshot.go:158`）。任一插件返回 `Terminate` 后，后面的拦截器都不再执行；前面的插件改写过的 Body 会传给后面的插件（`adapters_interceptors.go:200-226`）。

| 检查项 | billing 先（100 > 1） | moderation 先（200 > 100） |
|---|---|---|
| 两个插件都注册成功，管理 API 和页面互不冲突 | ✅ | ✅ |
| 正常请求两者都通过，并被 billing 计费 | ✅ | ✅ |
| 违规请求返回 moderation 的 403，上游 0 次 | ✅ | ✅ |
| 被拦截的请求**不计费**（billing 只在 `usage.handle` 中计费，被拦截的请求没有用量） | ✅ | ✅ |
| 连续 5 次被拦截后，正常请求仍能放行（并发上限为 1，**没有泄漏并发名额**：被拒绝时 billing 会在 `request.complete` 中释放名额） | ✅ | ✅ |
| 名额被一个慢请求占用时，再并发一个违规请求 | billing 返回 429，**不会调用审核 API** | moderation 返回 403，billing 不参与 |
| 未绑定的 Key / 未匹配的模型：不审核，billing 照常生效 | ✅ | ✅ |

结论与建议：
- 两种顺序都能正常工作，没有冲突。
- **默认（billing 先）**：额度不足或并发已满的请求不会消耗审核 API 的调用量。代价是违规请求在审核期间会短暂占用一个并发名额；如果套餐是“首次请求开始计时”，一条被拦截的请求也可能让计时提前开始。
- **moderation 先**：违规请求完全进不了计费插件。代价是额度不足的请求也会先调用一次审核 API。
- 如果还装了其他会**改写请求体**的拦截器插件，它的 priority 必须高于 cpa-moderation，否则它注入的内容不会被审核。

仍未覆盖：其他插件通过 `host.model.execute` 发起的嵌套请求能否带上原始 Key 的 caller_scope（例如 claude-web-search-router）；由 frontend-auth 类插件提供的 Key。

## 8. 对照官方插件开发文档（https://help.router-for.me/cn/plugin/development.html，2026-11-25）

| 文档要求 | 状态 | 说明 |
|---|---|---|
| CGO 编译的原生动态库，导出 `cliproxy_plugin_init`，填写 call/free_buffer/shutdown | ✅ | `cmd/cpa-moderation/main.go` |
| 插件 ID = 文件名，符合 `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`，放在 `plugins/` 或 `plugins/<GOOS>/<GOARCH>/` | ✅ | `cpa-moderation.so/.dll` |
| JSON 信封 `{ok,result}` / `{ok,error}`，字节字段使用 base64 | ✅ | |
| `plugin.register` / `plugin.reconfigure` 读取 `config_yaml`，插件自行校验 | ✅ | 非法值进入 fail-closed 状态；**未知字段只警告不失败**（文档要求兼容旧配置，CPA 管理接口也可能写入额外字段），警告会显示在状态接口和页面上 |
| `plugin.shutdown` | ✅ | 函数表的 shutdown 和 RPC 方法 `plugin.shutdown` 都已处理（本轮补上） |
| `ConfigFields` 类型为 string/number/integer/boolean/enum/array/object | ✅ | `remote_images` 改为 enum + EnumValues；对象类型的默认值改为使用 YAML 键名，管理界面写回后可以直接加载（本轮修复，有往返测试） |
| 只声明实际实现的能力 | ✅ | `request_interceptor`（after 阶段声明 omit body）、`management_api` |
| 管理 API 放在 `/v0/management/...` 下（需管理密钥），页面放在 `/v0/resource/plugins/<id>/...` | ✅ | 不与宿主的 `/plugins/{id}/enabled`、`/config` 冲突 |
| 页面只做展示，敏感操作走带密钥的管理 API；脚本随插件打包，不加载第三方脚本 | ✅ | 单文件 HTML，CSP `default-src 'none'`、`connect-src 'self'`；同源复用 CPAMC 的密钥 |
| 资源路径不含空格、`:`、`*`、`..` | ✅ | `/ui` |
| 不记录 Key、token、凭证或敏感请求体 | ✅ | 审计和日志只记录 ID、计数和类别，有测试检查 |
| 日志走 `host.log` | ✅ | 本轮改为优先使用 `host.log`，宿主不可用时回退到 stderr |
| 插件自身的 HTTP 走 `host.http.*` | ⚠️ **有意偏离** | 审核请求使用插件内的 `net/http`。原因：`host.http.do` 没有按次调用的超时（examples README："provides explicit cancellation, not a host-managed per-call timeout"），而审核必须在有限时间内返回，否则会让请求一直挂着。插件自带超时、并发上限，以及 `openai.proxy_url` 代理配置。代价是不会经过 CPA 的 `requests.proxy-url` 和 HTTP 日志。后续可以用 `host.http.operation_open/cancel` 实现超时后再切换 |
| 模型调用走 `host.model.*`，不复制宿主凭证 | ✅ 不适用 | 插件不调用生成模型，只用独立的审核 Key（环境变量） |
| 最小验证：`GET /v0/management/plugins` 显示 `registered: true`、`effective_enabled: true` | ✅ | 已实测，菜单「CPA Moderation」可见 |
| `X-CPA-SUPPORT-PLUGIN: 1` | ⚠️ 环境原因 | 本机测试用的 CPA 是不带 CGO 编译的（Windows 不需要 CGO 也能加载插件），所以返回 0；官方 Docker 镜像使用 `CGO_ENABLED=1` 编译，应返回 1，需要在 Docker 环境中复核 |
| 插件商店：`<id>_<version>_<goos>_<goarch>.zip`（zip 根目录直接放库文件）+ `checksums.txt`，`repository` 必须是 `https://github.com/{owner}/{repo}` | ✅ | `scripts/build.sh` + `scripts/package.py` + `release.yml`；已用 CPA 安装器和真实的商店安装接口验证，见 docs/release.md |
