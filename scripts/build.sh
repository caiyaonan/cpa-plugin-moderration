#!/usr/bin/env bash
# Build the plugin library for one or more targets into dist/build/<goos>_<goarch>/.
#
#   scripts/build.sh linux/amd64 linux/arm64 windows/amd64      # cross-compile with zig
#   scripts/build.sh darwin/arm64 darwin/amd64                  # on macOS, uses clang
#
# Linux targets use a glibc 2.17 baseline (zig) so the library loads on old
# and new distributions alike, including the official debian:bookworm image.
# Set ZIG to override the zig command (default: "zig", falling back to
# "python3 -m ziglang" / "python -m ziglang").
set -euo pipefail
cd "$(dirname "$0")/.."

ID=cpa-moderation
[ $# -gt 0 ] || { echo "usage: $0 <goos/goarch>..." >&2; exit 2; }

zig_cmd() {
  if [ -n "${ZIG:-}" ]; then echo "$ZIG"; return; fi
  if command -v zig >/dev/null 2>&1; then echo zig; return; fi
  for py in python3 python; do
    if command -v $py >/dev/null 2>&1 && $py -m ziglang version >/dev/null 2>&1; then echo "$py -m ziglang"; return; fi
  done
  echo "zig not found: install zig or 'pip install ziglang'" >&2; exit 1
}

for target in "$@"; do
  goos=${target%/*}; goarch=${target#*/}
  case "$goos" in
    linux) ext=so ;;
    windows) ext=dll ;;
    darwin) ext=dylib ;;
    *) echo "unsupported goos $goos" >&2; exit 2 ;;
  esac
  case "$goos/$goarch" in
    linux/amd64)   cc="$(zig_cmd) cc -target x86_64-linux-gnu.2.17" ;;
    linux/arm64)   cc="$(zig_cmd) cc -target aarch64-linux-gnu.2.17" ;;
    windows/amd64) cc="$(zig_cmd) cc -target x86_64-windows-gnu" ;;
    windows/arm64) cc="$(zig_cmd) cc -target aarch64-windows-gnu" ;;
    darwin/amd64)  cc="clang -arch x86_64 -mmacosx-version-min=11.0" ;;
    darwin/arm64)  cc="clang -arch arm64 -mmacosx-version-min=11.0" ;;
    *) echo "unsupported target $goos/$goarch" >&2; exit 2 ;;
  esac
  out="dist/build/${goos}_${goarch}"
  mkdir -p "$out"
  echo ">> $goos/$goarch ($cc)"
  # Pin a baseline instruction set so the library does not SIGILL on older CPUs.
  GOOS=$goos GOARCH=$goarch GOAMD64=v1 GOARM64=v8.0 CGO_ENABLED=1 CC="$cc" \
    go build -tags cshared -buildmode=c-shared -trimpath -buildvcs=false -ldflags "-s -w" \
    -o "$out/$ID.$ext" ./cmd/cpa-moderation 2> >(grep -vE "warning:|note:|^ *\||^ *[0-9]+ \||^In file included|warnings? generated" >&2)
  rm -f "$out/$ID.h"
done
