#!/bin/sh
# 使い捨ての swtpm を起動して attest_flow を実行する。
# 使い方: ./run-swtpm.sh   環境変数: SWTPM_PORT(既定 2321)
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${SWTPM_PORT:-2321}

command -v swtpm >/dev/null || { echo "swtpm が必要" >&2; exit 1; }
[ -x "$HERE/attest_flow" ] || { echo "先に make を実行" >&2; exit 1; }

TMP=$(mktemp -d)
PID=""
cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

swtpm socket --tpm2 --tpmstate dir="$TMP" \
    --server type=tcp,port="$PORT" --ctrl type=tcp,port=$((PORT + 1)) \
    --flags not-need-init,startup-clear &
PID=$!
sleep 0.5

"$HERE/attest_flow" --tcti "swtpm:host=127.0.0.1,port=$PORT"
