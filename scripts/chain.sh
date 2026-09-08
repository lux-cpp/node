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
# Every process is handed the SAME committee file and the SAME peer list, which
# is how a real operator describes a network — see scripts/cluster.sh.
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

echo "== writing the network down: $N validators publish, once =="
peers=""
for i in $(seq 0 $((N - 1))); do
  "$NODED" --data "$TMP/v$i" --publish >>"$TMP/committee.txt"
  peers="${peers:+$peers,}127.0.0.1:$((BASE + i))"
done

echo "== booting $N noded processes (consensus $BASE.., rpc $RPC..) =="
for i in $(seq 0 $((N - 1))); do
  "$NODED" --data "$TMP/v$i" --committee "$TMP/committee.txt" --peers "$peers" \
           --rpc-port $((RPC + i)) --deadline-ms 8000 >"$TMP/node$i.log" 2>&1 &
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
# THE FRONTIER, NOT A HISTORICAL HEIGHT. These nodes are frontier-resident light
# nodes: a block below the tip is refused, not served, so asking every node for
# height h-2 gets five refusals — and comparing five refusals to each other is a
# check that passes when nothing works. Sample the tip from all five instead,
# and only compare when they are at the same height; a root that is not 32 bytes
# of hex fails, so an empty answer can never pass.
root_at() { # root_at <node-index> -> "<number> <stateRoot>"
  curl -s --max-time 10 -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest",false]}' \
    "http://127.0.0.1:$((RPC + $1))/v1/chain/C/rpc" \
  | sed -n 's/.*"number":"\([^"]*\)".*"stateRoot":"\([^"]*\)".*/\1 \2/p'
}
HEIGHT=""; ROOT0=""; SEEN=()
for _ in $(seq 1 40); do
  SEEN=(); HEIGHT=""; agreed=1
  for i in $(seq 0 $((N - 1))); do
    h=""; r=""
    read -r h r <<<"$(root_at "$i")" || true
    SEEN+=("$h $r")
    [[ -z "$HEIGHT" ]] && HEIGHT="$h"
    [[ "$h" == "$HEIGHT" ]] || agreed=0
  done
  [[ "$agreed" == 1 && -n "$HEIGHT" ]] && break
  sleep 0.25
done
ROOT0="${SEEN[0]:-}"; ROOT0="${ROOT0#* }"
if [[ "$ROOT0" =~ ^0x[0-9a-f]{64}$ && "$ROOT0" != "0x$(printf '0%.0s' {1..64})" ]]; then
  echo "  ok    the tip at $HEIGHT carries a real state root $ROOT0"
else
  echo "  FAIL  the tip carries no usable state root: '$ROOT0'"; fail=1
fi
for i in $(seq 0 $((N - 1))); do
  check "node $i at $HEIGHT" "${SEEN[$i]}" "$HEIGHT $ROOT0"
done
# The funded genesis account, read out of the state the root commits to.
check "the genesis account holds its allocation" \
  "$(rpc 0 eth_getBalance '["0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","latest"]')" \
  "0x21e19e0c9bab24000"

echo
if (( fail )); then echo "FAIL"; exit 1; fi
echo "PASS — $N nodes serving one C-Chain, agreeing on the root they executed"
