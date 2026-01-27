#!/usr/bin/env bash
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "Please source this script: source $0" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TONGSUO_HOME="${TONGSUO_HOME:-$ROOT/third_party/tongsuo-install}"

if [[ ! -d "$TONGSUO_HOME" ]]; then
  echo "Tongsuo not found at $TONGSUO_HOME. Run: git submodule update --init --recursive" >&2
  return 1 2>/dev/null || exit 1
fi

LIBDIR="$TONGSUO_HOME/lib"
if [[ ! -d "$LIBDIR" ]]; then
  LIBDIR="$TONGSUO_HOME"
fi

export TONGSUO_HOME
export DYLD_LIBRARY_PATH="$LIBDIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"

echo "TONGSUO_HOME set to $TONGSUO_HOME"
echo "DYLD_LIBRARY_PATH updated with $LIBDIR"