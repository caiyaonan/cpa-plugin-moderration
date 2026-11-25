# 发布与插件商店

## 产物格式（CLIProxyAPI v8.1.2 `internal/pluginstore` 实测）

每个 GitHub Release 包含：

```text
cpa-moderation_<version>_linux_amd64.zip
cpa-moderation_<version>_linux_arm64.zip
cpa-moderation_<version>_windows_amd64.zip
cpa-moderation_<version>_darwin_amd64.zip
cpa-moderation_<version>_darwin_arm64.zip
checksums.txt            # "<sha256>  <zip 文件名>"
```

- zip 根目录直接放 `cpa-moderation.<so|dll|dylib>`，不能有子目录。
- `<version>` = Release tag 去掉开头的 `v`，**必须等于** `internal/plugin/types.go` 中的 `Version`。CPA 会按 tag 推导出版本号，再拼出 zip 文件名去找对应文件。
- 商店安装后，库文件位于 `plugins/<goos>/<goarch>/cpa-moderation-v<version>.<ext>`。CPA 会在插件配置中写入 `store:` 块来固定版本（插件会识别并忽略它）。
- Linux 库以 glibc 2.17 为基线构建（zig），实际只引用到 GLIBC 2.3 的符号，可在官方镜像 debian:bookworm 等新旧发行版上加载。
- 指令集基线为 `GOAMD64=v1` / `GOARM64=v8.0`，避免在老 CPU 上触发 SIGILL。

## 发布步骤

1. 修改 `internal/plugin/types.go` 中的 `Version`（例如 `0.1.1`），提交并推送到 main。
2. 打 tag 并推送：

   ```bash
   git tag -a v0.1.1 -m "v0.1.1"
   git push origin v0.1.1
   ```

3. `.github/workflows/release.yml` 会自动执行：检查（gofmt / vet / race / 页面脚本）→ 构建 Linux 和 Windows（ubuntu + zig）与 macOS（macos-15 + clang）→ 打包 → 校验 `sha256sum -c` → 创建 Release 并上传 zip 和 `checksums.txt`。tag 与 `Version` 不一致时会直接失败。

本地打包（不发布）：

```bash
pip install ziglang==0.17.1
bash scripts/build.sh linux/amd64 linux/arm64 windows/amd64
python3 scripts/package.py --tag v0.1.0     # 输出到 dist/release/
```

## 上架官方插件商店

官方源：`https://raw.githubusercontent.com/router-for-me/CLIProxyAPI-Plugins-Store/main/registry.json`（`schema_version: 1`）。

1. 先发布至少一个包含上述资产的 GitHub Release（商店安装的是 **latest release**）。
2. 向 `router-for-me/CLIProxyAPI-Plugins-Store` 提交 PR，把 `dist/release/registry-entry.json` 的内容加入 `registry.json` 的 `plugins` 数组。字段与官方现有条目一致：`id`、`name`、`description`、`author`、`version`、`repository`、`homepage`、`license`、`tags`、`locales`。
3. 维护者合并之前，不能声称已上架。

## 自建或第三方商店源

在 CPA 配置中加入额外的源：

```yaml
plugins:
  store-sources:
    - "https://example.com/cpa/registry.json"
```

`schema_version: 1` 的条目只需要 `repository`，CPA 会从 GitHub latest release 下载。`schema_version: 2` 还支持 `install.type: direct`，可以直接给出每个平台 zip 的 URL、sha256 和 size，适合内网环境。HTTP（非 HTTPS）源需要在 `plugins.store-auth` 中为该前缀配置 `allow-insecure: true`。

## 本地验证记录（2026-11-25）

- 用 CPA 自身的 `SelectReleaseAssets` → `ParseChecksums` → `VerifyChecksum` → `InstallArchive` 校验了 linux/amd64、linux/arm64、windows/amd64 三个包，全部通过。
- 在真实 CPA v8.1.2 中搭建本地 registry v2 源，通过 `POST /v0/management/plugin-store/cpa-moderation/install` 完成安装：下载、校验、解压、**热加载并注册**（`restart_required: false`），`registered: true`、`effective_enabled: true`。重启 CPA 后依然能加载，状态无警告。
- 尚未验证：GitHub Release 路径的实际下载（需要先发布一次）、macOS 产物（需要 macos runner 或 Mac 本机）、Linux 产物在 Docker 中的实际加载。
