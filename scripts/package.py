#!/usr/bin/env python3
"""Package built libraries into CLIProxyAPI plugin-store release assets.

Reads dist/build/<goos>_<goarch>/cpa-moderation.<ext> and writes, into dist/release/:

    cpa-moderation_<version>_<goos>_<goarch>.zip   (library at the zip root)
    checksums.txt                                   (sha256, "<hash>  <name>")
    registry-entry.json                             (entry for a registry v1 store)

The version comes from internal/plugin/types.go. With --tag, the tag (leading
"v" stripped) must equal that version, because the store installs the GitHub
release tag's version and the zip names must match it.

Usage: python3 scripts/package.py [--tag v0.1.0]
"""
import argparse
import hashlib
import json
import os
import re
import sys
import zipfile

PLUGIN_ID = "cpa-moderation"
EXT = {"linux": "so", "windows": "dll", "darwin": "dylib"}
# Fixed timestamp makes the zip bytes reproducible for identical libraries.
ZIP_DATE = (2020, 1, 1, 0, 0, 0)


def read_version(root):
    src = open(os.path.join(root, "internal", "plugin", "types.go"), encoding="utf-8").read()
    m = re.search(r'Version\s*=\s*"([^"]+)"', src)
    if not m:
        sys.exit("cannot find Version in internal/plugin/types.go")
    return m.group(1)


def read_repo(root):
    src = open(os.path.join(root, "internal", "plugin", "types.go"), encoding="utf-8").read()
    return re.search(r'GitHubRepository\s*=\s*"([^"]+)"', src).group(1)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", help="release tag; must match the plugin Version")
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    version = read_version(root)
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", version):
        sys.exit(f"version {version!r} is not a valid plugin version")
    if args.tag is not None:
        tag_version = args.tag[1:] if args.tag[:1] in ("v", "V") else args.tag
        if tag_version != version:
            sys.exit(f"tag {args.tag} does not match plugin Version {version}; bump internal/plugin/types.go first")

    build = os.path.join(root, "dist", "build")
    out = os.path.join(root, "dist", "release")
    os.makedirs(out, exist_ok=True)
    for name in os.listdir(out):
        os.remove(os.path.join(out, name))

    assets = []
    for target in sorted(os.listdir(build)) if os.path.isdir(build) else []:
        goos, _, goarch = target.partition("_")
        if goos not in EXT:
            continue
        lib = os.path.join(build, target, f"{PLUGIN_ID}.{EXT[goos]}")
        if not os.path.isfile(lib):
            sys.exit(f"missing {lib}")
        zip_name = f"{PLUGIN_ID}_{version}_{goos}_{goarch}.zip"
        info = zipfile.ZipInfo(f"{PLUGIN_ID}.{EXT[goos]}", date_time=ZIP_DATE)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (0o100755 & 0xFFFF) << 16  # regular file, rwxr-xr-x
        info.create_system = 3  # unix, so the mode bits are honored
        with zipfile.ZipFile(os.path.join(out, zip_name), "w") as z, open(lib, "rb") as f:
            z.writestr(info, f.read())
        assets.append(zip_name)
        print(f"packaged {zip_name}")
    if not assets:
        sys.exit("no built libraries found under dist/build; run scripts/build.sh first")

    with open(os.path.join(out, "checksums.txt"), "w", encoding="utf-8", newline="\n") as f:
        for name in assets:
            f.write(f"{sha256(os.path.join(out, name))}  {name}\n")

    entry = {
        "id": PLUGIN_ID,
        "name": "CPA Moderation",
        "description": "Moderate requests from selected API keys and models with local wordlists and the OpenAI moderation API before they reach upstream.",
        "author": "caiyaonan",
        "version": version,
        "repository": read_repo(root),
        "homepage": read_repo(root),
        "license": "MIT",
        "tags": ["moderation", "safety", "request-interceptor"],
        "locales": {
            "zh-CN": {
                "name": "CPA 内容审核",
                "description": "对指定 Key 和模型的请求，在发往上游前用本地词库和 OpenAI 审核接口检查文本与图片，违规直接拒绝。",
            }
        },
    }
    with open(os.path.join(out, "registry-entry.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(entry, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"wrote checksums.txt and registry-entry.json for {version}")


if __name__ == "__main__":
    main()
