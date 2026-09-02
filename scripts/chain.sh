#!/usr/bin/env bash
# Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# chain.sh — boot a cluster of noded PROCESSES and assert that what they serve
# over JSON-RPC is a real chain: the C-Chain's id, a height that advances, and —
# the one that matters — the SAME state root at the same height on every node.
#
# That last check is the whole point. Each node executed the block through its
# own cevm and signed the root ITS execution produced; agreeing on the root at a
# height is therefore agreement about an executed result, not about a name. A
# node whose EVM diverged would show a different root here, and would already
# have failed to certify.
#
# Usage: scripts/chain.sh [noded] [consensus-base-port] [rpc-base-port] [n]
set -euo pipefail

NODED="${1:-build/noded}"
BASE="${2:-19600}"
RPC="${3:-19850}"
N="${4:-5}"

[[ -x "$NODED" ]] || { echo "noded not found at: $NODED" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

TMP="$(mktemp -d)"
pids=()
# SIGTERM, and let each node finish what it is doing. noded stops at the height
# it is in; killing it harder would leave the question of whether it had.
cleanup() {
  for p in "${pids[@]:-}"; do kill -TERM "$p" 2>/dev/null || true; done
  for p in "${pids[@]:-}"; do
    for _ in $(seq 1 40); do kill -0 "$p" 2>/dev/null || break; sleep 0.25; done
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

fail=0
check() { if [[ "$2" == "$3" ]]; then echo "  ok    $1"; else echo "  FAIL  $1"; echo "          want $3"; echo "          got  $2"; fail=1; fi; }

rpc() { # rpc <node-index> <method> [params-json]
  curl -s --max-time 10 -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" \
    "http://127.0.0.1:$((RPC + $1))/v1/chain/C/rpc" \
  | sed -n 's/.*"result":"\?\([^,"}]*\)"\?.*/\1/p'
}

echo "== booting $N noded processes (consensus $BASE.., rpc $RPC..) =="
for i in $(seq 0 $((N - 1))); do
  "$NODED" --index "$i" --n "$N" --base-port "$BASE" --rpc-port $((RPC + i)) \
           --deadline-ms 8000 >"$TMP/node$i.log" 2>&1 &
  pids+=("$!")
done

# Wait for the RPC to answer rather than sleeping a guess at how long boot takes.
for _ in $(seq 1 60); do [[ -n "$(rpc 0 eth_chainId)" ]] && break; sleep 0.5; done

echo "== the chain identifies itself =="
check "eth_chainId is the C-Chain's local id"   "$(rpc 0 eth_chainId)" "0x7a69"
CLIENT="$(rpc 0 web3_clientVersion)"
[[ -n "$CLIENT" ]] && echo "  ok    web3_clientVersion = $CLIENT" || { echo "  FAIL  web3_clientVersion is empty"; fail=1; }

echo "== the height advances =="
H0="$(rpc 0 eth_blockNumber)"
sleep 3
H1="$(rpc 0 eth_blockNumber)"
if (( H1 > H0 )); then echo "  ok    eth_blockNumber $H0 -> $H1"; else echo "  FAIL  height did not advance ($H0 -> $H1)"; fail=1; fi

echo "== every node executed the same block to the same root =="
# A height every node has certainly accepted by now.
HEX=$(printf '0x%x' $(( H0 > 2 ? H0 - 2 : 1 )))
ROOT0=""
for i in $(seq 0 $((N - 1))); do
  R="$(curl -s --max-time 10 -X POST -H 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByNumber\",\"params\":[\"$HEX\",false]}" \
        "http://127.0.0.1:$((RPC + i))/v1/chain/C/rpc" \
      | sed -n 's/.*"stateRoot":"\([^"]*\)".*/\1/p')"
  [[ -z "$ROOT0" ]] && ROOT0="$R"
  check "node $i state root at block $HEX" "$R" "$ROOT0"
done

echo "== the genesis root is a real root, not a constant =="
G="$(curl -s --max-time 10 -X POST -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' \
      "http://127.0.0.1:$RPC/v1/chain/C/rpc" | sed -n 's/.*"stateRoot":"\([^"]*\)".*/\1/p')"
if [[ "$G" =~ ^0x[0-9a-f]{64}$ && "$G" != "0x$(printf '0%.0s' {1..64})" ]]; then
  echo "  ok    genesis state root $G"
else
  echo "  FAIL  genesis state root looks wrong: $G"; fail=1
fi
# The funded genesis account, read out of the state the root commits to.
check "the genesis account holds its allocation" \
  "$(rpc 0 eth_getBalance '["0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","latest"]')" \
  "0x21e19e0c9bab24000"

echo
if (( fail )); then echo "FAIL"; exit 1; fi
echo "PASS — $N nodes serving one C-Chain, agreeing on the root they executed"
