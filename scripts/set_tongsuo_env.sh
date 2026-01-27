#!/usr/bin/env bash
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "Please source this script: source $0" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS="$(uname -s)"

case "$OS" in
  Linux*)  . "$SCRIPT_DIR/set_tongsuo_env_linux.sh" ;;
  Darwin*) . "$SCRIPT_DIR/set_tongsuo_env_macos.sh" ;;
  *)
    echo "Unsupported OS: $OS" >&2
    return 1 2>/dev/null || exit 1
    ;;
 esac