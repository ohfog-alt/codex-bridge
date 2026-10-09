#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -d "$HOME/tools/node-v24.16.0-linux-arm64/bin" ]; then
  export PATH="$HOME/tools/node-v24.16.0-linux-arm64/bin:$PATH"
fi

export CODEX_BIN="${CODEX_BIN:-$HOME/.codex/packages/standalone/current/bin/codex}"
export CODEX_APP_SERVER_ARGS="${CODEX_APP_SERVER_ARGS:-app-server --stdio}"
export CODEX_BRIDGE_LISTEN_HOST="${CODEX_BRIDGE_LISTEN_HOST:-127.0.0.1}"
export CODEX_BRIDGE_LISTEN_PORT="${CODEX_BRIDGE_LISTEN_PORT:-4747}"

exec node "$script_dir/controller-bridge.mjs"
