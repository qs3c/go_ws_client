#!/usr/bin/env bash
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "Please source this script: source $0" >&2
  exit 1
fi

DEFAULT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -d "$PWD/third_party/tongsuo-install" ]]; then
  ROOT="$PWD"
else
  ROOT="$DEFAULT_ROOT"
fi
TONGSUO_HOME="${TONGSUO_HOME:-$ROOT/third_party/tongsuo-install}"

if [[ ! -d "$TONGSUO_HOME" ]]; then
  echo "Tongsuo not found at $TONGSUO_HOME. Run: git submodule update --init --recursive" >&2
  return 1 2>/dev/null || exit 1
fi

BINDIR="$TONGSUO_HOME/bin"

export TONGSUO_HOME
export PATH="$BINDIR:$PATH"

echo "TONGSUO_HOME set to $TONGSUO_HOME"
echo "PATH updated with $BINDIR"