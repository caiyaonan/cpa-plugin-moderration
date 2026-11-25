# cpa-moderation

[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 原生插件：对**指定 API Key × 指定模型**的请求，在 CPA 选择上游凭证之前，用本地词库和 OpenAI `omni-moderation-latest` 审核文本与图片。违规就直接拒绝，请求不会到达上游。

状态：核心功能和管理页面已完成（v0.1.0）。规格见 [docs/CPA-Moderation-Development-v1.1.md](docs/CPA-Moderation-Development-v1.1.md)，宿主实测结果见 [docs/compatibility.md](docs/compatibility.md)。

## 行为

- 只审核绑定了规则的 Key 发出的、模型匹配规则的请求；**其他请求不做任何审核**。
- 模型匹配看客户端请求的模型名（别名也要写进规则），支持 `*` `?` 通配符，区分大小写。
- 支持的格式：OpenAI chat、responses（含 Codex）、images generations / edits（JSON 和 multipart）、Claude messages、Gemini。
- 多条规则同时命中时取最严：检查项取并集，`on_error` 和 `unsupported_content` 只要有一条是 deny 就 deny，类别只有在所有命中规则都设为 log 时才只记录不拦截。
- 故障关闭：插件内部错误或 panic、配置损坏、审核服务不可用，一律拒绝而不是放行。原因见 compatibility.md §5：宿主遇到插件错误会直接放行，插件 panic 会让整个 CPA 崩溃。
- 请求体不会被修改，审计日志不记录原文、命中词、分数或 Key。

| 情况 | HTTP | code |
|---|---|---|
| 违规（词库或审核接口判定） | 403 | `content_policy_violation` |
| 无法解析，或包含不支持的内容（音频、文件等） | 400 | `moderation_input_invalid` |
| 超出大小或数量限制 | 413 | `moderation_input_too_large` |
| 审核服务不可用，或插件配置异常 | 503 | `moderation_unavailable` |
| 本地并发已满 | 429 | `moderation_rate_limited` |

错误体按客户端格式返回（OpenAI、Anthropic 或 Google 风格），并带上 `request_id`。

## 安装（推荐：本仓库自带的商店源）

在 CLIProxyAPI 的 `config.yaml` 中加入：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  store-sources:
    - "https://raw.githubusercontent.com/caiyaonan/cpa-plugin-moderration/main/registry.json"
```

重启 CPA 后，在 CPAMC 的插件商店里找到「CPA Moderation」点安装即可；也可以直接调用管理接口：

```bash
curl -X POST -H "Authorization: Bearer <管理密钥>"   "http://<CPA 地址>/v0/management/plugin-store/cpa-moderation/install"
```

CPA 会从本仓库的 GitHub Release 下载对应平台的包，校验 `checksums.txt` 后安装到 `plugins/<系统>/<架构>/` 并热加载，不需要重启。发布新版本后，商店里会显示有更新。

配置审核用的 OpenAI API Key，二选一（插件配置优先）。所有配置项都能在 CPAMC 的插件配置页里逐项填写，完整列表和默认值见 [examples/config.yaml](examples/config.yaml)：

- **方式一（推荐）**：在 CPAMC「插件 → cpa-moderation → 编辑配置」里填写 `api_key` 后保存，立即生效；或者直接写进 `config.yaml`：

```yaml
plugins:
  configs:
    cpa-moderation:
      api_key: "sk-proj-..."
```

- **方式二**：不写 `api_key`，设置环境变量 `OPENAI_MODERATION_API_KEY`（Docker 中用 `environment:`，修改后需要 `docker compose up -d` 重建容器）。

写在插件配置里时，修改后会自动热更新，不需要重启。插件不会在状态、日志、审计、事件或错误信息中输出 Key。但 CPA 自己的管理接口 `GET /v0/management/plugins/cpa-moderation/config` 会原样返回插件配置，持有管理密钥的人能看到它；另外要注意 `config.yaml` 的文件权限和备份。

Docker 部署时还要把 `plugins` 目录挂载出来（例如 `./plugins:/CLIProxyAPI/plugins`）：插件文件和规则数据都在里面，不挂载的话重建容器就会丢失。

装好后打开 `http://<CPA 地址>/v0/resource/plugins/cpa-moderation/ui` 配置规则。也可以从 [Releases](https://github.com/caiyaonan/cpa-plugin-moderration/releases) 手动下载 zip，把里面的库文件放进 `plugins/` 后重启。

## 构建

需要 Go 1.24 以上和一个 C 编译器（CGO）。下面用 zig 作为 C 编译器（`pip install ziglang`）：

```bash
# Linux amd64（在 Linux 或 manylinux 容器中执行）
CGO_ENABLED=1 GOAMD64=v1 go build -tags cshared -buildmode=c-shared -trimpath -o dist/cpa-moderation.so ./cmd/cpa-moderation
# Windows amd64
CGO_ENABLED=1 CC="python -m ziglang cc -target x86_64-windows-gnu" GOAMD64=v1 go build -tags cshared -buildmode=c-shared -trimpath -o dist/cpa-moderation.dll ./cmd/cpa-moderation
```

文件名必须是 `cpa-moderation.<ext>`，因为文件名就是插件 ID。

也可以用脚本一次性构建多个平台并打包成插件商店格式：

```bash
bash scripts/build.sh linux/amd64 linux/arm64 windows/amd64
python3 scripts/package.py --tag v0.1.0     # 输出到 dist/release/：各平台 zip + checksums.txt
```

推送 `v*` tag 会触发 GitHub Actions 构建 5 个平台的包并自动发布 Release。发布流程和商店上架方法见 [docs/release.md](docs/release.md)。

## 测试

```bash
go vet ./... && go test ./...
```

`go test -race` 需要在 Linux 上执行（Windows 上的 zig 工具链缺少 tsan 依赖的系统库）。

真实宿主 e2e：参照 `poc/e2e/`，启动 `poc/mock_upstream.py 18081`（它同时模拟上游和 `/v1/moderations`），再设置 `OPENAI_MODERATION_API_KEY=test-moderation-key` 启动 CPA，然后执行 `bash run_e2e.sh`。当前结果：36/36 通过（CPA v8.1.2，Windows）。

## 管理页面

地址：`http(s)://<CPA 地址>/v0/resource/plugins/cpa-moderation/ui`。在 CPAMC / CPAMP 里会显示为侧边栏菜单「CPA Moderation」。

- 页面本身不带任何数据。打开后需要输入 CPA 管理密钥；如果同一地址下的 CPAMC 已经登录，会直接复用它的密钥。密钥只保存在当前标签页。
- **概览**：健康状态、审核 Key 是否已配置、计数、审核接口连通性测试。
- **API Key**：从 CPA 同步 Key，填写备注，勾选或批量绑定审核规则。
- **审核规则**：填写模型（可从 CPA 模型列表勾选，实时显示匹配结果，并提示不匹配任何模型的规则），以及接口格式、检查项、角色、历史范围、词库、只记录不拦截的类别、故障策略。
- **词库**：关键词和正则，可导入导出 txt（必须是 UTF-8）。
- **模拟测试**：用已保存的配置评估一个请求，不转发；可以选择是否同时调用审核接口。
- **审核记录**：最近的审核事件，按结果筛选，不包含原文。

所有修改先保存在页面里，点「保存」后才一次性写入，并立即生效。有人同时修改时会提示冲突，不会覆盖对方的修改。

## 配置与管理 API

静态配置见 [examples/config.yaml](examples/config.yaml)。规则、词库和 Key 绑定保存在 `state_file` 里，通过管理 API 修改（继承 CPA 管理密钥鉴权）：

| 方法 | 路径（前缀 `/v0/management/plugins/cpa-moderation`） | 说明 |
|---|---|---|
| GET | `/status` | 健康状态、计数、OpenAI Key 是否已配置 |
| GET / PUT | `/state` | 读取或整体替换规则、词库、绑定；PUT 必须带上当前 `revision`，否则返回 409 |
| POST | `/keys/sync` | `{"keys":[...]}` 传入 CPA 的 Key 列表，只保存哈希和打码预览 |
| POST | `/simulate` | 模拟评估一个请求，不转发；`call_provider:true` 时才真正调用审核接口 |
| POST | `/provider/test` | 用一段无害文本测试审核接口连通性 |
| GET | `/events?limit=&outcome=` | 最近的审核事件 |
| GET | `/models` | CPA 各凭证可服务的模型名（包含别名），供页面选择使用 |

> Windows 上调用管理 API 时，请用 `--data-binary @file.json` 发送 UTF-8 文件。PowerShell 或 Git Bash 下的 curl 会把命令行参数里的中文转成 GBK，插件会拒绝这类乱码关键词。

## 与其他插件共存

已和 cpa-key-billing 在同一个 CPA 中实测：两种执行顺序都没有冲突，被拦截的请求不计费，也不会泄漏并发名额（详见 [docs/compatibility.md](docs/compatibility.md) §7）。执行顺序由 `priority` 决定，数值大的先执行：
- 保持默认 `priority: 1`：其他插件先执行，额度不足的请求不会消耗审核调用。
- 调高到超过其他插件（例如 200）：违规请求完全不会进入其他插件。
- 会改写请求体的插件，priority 必须高于本插件，否则它注入的内容不会被审核。

## 对照官方插件开发文档

已逐项对照 [插件开发文档](https://help.router-for.me/cn/plugin/development.html)，结果见 [docs/compatibility.md](docs/compatibility.md) §8。有意偏离的一项：审核请求没有走 `host.http.do`（它没有按次调用的超时），改用插件自带的、有超时和并发限制的 HTTP 客户端。发布包已按商店格式实现，并在真实 CPA 中通过商店接口安装验证过。

## 已知限制

- 页面只有中文界面；审计记录页显示的是内存中的最近 1000 条，历史记录需要查看 `audit_file`。
- 审计查询的持久化索引、Prometheus 指标、多节点同步尚未实现。
- `previous_response_id` 和 `conversation` 引用的历史保存在上游，无法审核，只记录在 notes 里。
- 设置 `enabled: false`、卸载插件，或宿主熔断插件时，审核都会失效。
- Linux / Docker 加载、Codex WebSocket、NewAPI 联调还没验证（见 compatibility.md §6）。

## 致谢

- [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)：插件 ABI、宿主契约和示例插件。
- [cpa-plugin-key-billing](https://github.com/haowang02/cpa-plugin-key-billing)（MIT）：C ABI 胶水代码、管理页挂载方式、Key 同步，以及同源复用 CPAMC 管理密钥的做法，本项目参照了其实现。

## 许可证

[MIT](LICENSE)
