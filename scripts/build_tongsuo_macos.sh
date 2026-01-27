#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/third_party/tongsuo"
BUILD="${TONGSUO_BUILD_DIR:-$ROOT/third_party/tongsuo-build}"
PREFIX="${TONGSUO_PREFIX:-$ROOT/third_party/tongsuo-install}"
CONFIG_OPTS="${TONGSUO_CONFIG_OPTS:-}"
INSTALL_TARGETS="${TONGSUO_INSTALL_TARGETS:-install}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN || echo 4)}"

if [[ ! -d "$SRC" ]]; then
  echo "Tongsuo source not found at $SRC. Run: git submodule update --init --recursive" >&2
  exit 1
fi
if [[ "$PREFIX" == "$SRC" ]]; then
  echo "Refusing to install into source directory. Set TONGSUO_PREFIX to a separate install path." >&2
  exit 1
fi

mkdir -p "$BUILD"
cd "$BUILD"

"$SRC/config" --prefix="$PREFIX" $CONFIG_OPTS
make -j"$JOBS"
make $INSTALL_TARGETS