#!/usr/bin/env bash
# Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# cluster.sh — N luxd validators as PROCESSES on the local chain (31337), each
# running its EVM as the cevm plugin, fed one transaction at a time, and held to
# one thing: every validator that is up accepts the same block at every height.
#
# The optional DOWN seat is configured in every committee and never started. Its
# windows lapse and the next window's proposer builds (the windower,
# engine.hpp), so a held-down seat costs its windows and nothing more; the
# "slot" each block was built in is printed, and a slot above 0 is a height
# whose first window was somebody else's.
#
# With IMPORT > 0 the chain does not start at genesis: the first IMPORT
# transactions are built into blocks by the cevm plugin alone (local_export,
# beside luxd) and written as an export, and every validator starts with
# --import-chain-data on it. Its tip is one no quorum decided, so each signs an
# anchor on it (engine.hpp); once α have, the rest of the transactions are built
# on top.
#
# Transactions go to the validators in turn and are relayed across the mesh, so
# whichever validator holds the window holds the transaction. They are
# test/local/txs.txt: transfers signed by the first Anvil/Hardhat account, the
# key luxd's local spec funds (src/luxd.cpp). A Cancun block that would owe a
# block gas cost is not built, so they are sent a block interval apart.
#
# Usage: scripts/cluster.sh LUXD CEVM [down] [import] [n] [mesh-port] [rpc-port]
set -uo pipefail

LUXD="${1:?luxd}"
CEVM="${2:?cevm}"
DOWN="${3:--1}"
IMPORT="${4:-0}"
N="${5:-5}"
BASE="${6:-19310}"
RPC="${7:-19410}"
TXS="$(cd "$(dirname "$0")/.." && pwd)/test/local/txs.txt"
FROM=0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266

TMP="$(mktemp -d)"
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill -TERM "$p" 2>/dev/null || true; done
  for p in "${pids[@]:-}"; do wait "$p" 2>/dev/null || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

fail=0
ok()   { echo "  ok    $1"; }
bad()  { echo "  FAIL  $1"; fail=1; }
call() { # call <seat> <method> <params-json> -> the raw answer
  curl -s --max-time 5 -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" \
    "http://127.0.0.1:$((RPC + $1))/v1/chain/c/rpc"
}
field() { sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p"; }

live=()
for i in $(seq 0 $((N - 1))); do [[ "$i" == "$DOWN" ]] || live+=("$i"); done

peers=""
for i in $(seq 0 $((N - 1))); do
  "$LUXD" --data "$TMP/v$i" --publish >>"$TMP/committee.txt"
  peers="${peers:+$peers,}127.0.0.1:$((BASE + i))"
done
imported=()
if (( IMPORT > 0 )); then
  made="$("$(dirname "$LUXD")/local_export" "$CEVM" "$TMP/local.rlp" "$TXS" "$IMPORT")" || { echo "FAIL  the export"; exit 1; }
  echo "== the export: $made"
  imported=(--import-chain-data "$TMP/local.rlp")
fi
for i in "${live[@]}"; do
  "$LUXD" --data "$TMP/v$i" --committee "$TMP/committee.txt" --peers "$peers" --vm "$CEVM" \
          --rpc-port $((RPC + i)) --deadline-ms 3000 "${imported[@]}" >"$TMP/node$i.log" 2>&1 &
  pids+=("$!")
done
if (( DOWN >= 0 )); then echo "== ${#live[@]} of $N validators up, seat $DOWN held down"; else echo "== $N validators up"; fi
for _ in $(seq 1 60); do grep -q "window" "$TMP/node${live[0]}.log" 2>/dev/null && break; sleep 0.5; done

if (( IMPORT > 0 )); then
  for i in "${live[@]}"; do
    for _ in $(seq 1 120); do grep -q "ANCHORED the imported tip at height $IMPORT " "$TMP/node$i.log" && break; sleep 0.5; done
    grep -q "ANCHORED the imported tip at height $IMPORT " "$TMP/node$i.log" \
      && ok "seat $i anchored the imported tip at height $IMPORT" || bad "seat $i did not anchor height $IMPORT"
  done
fi

sent=0
while read -r tx; do
  if (( sent < IMPORT )); then sent=$((sent + 1)); continue; fi
  seat="${live[$((sent % ${#live[@]}))]}"
  answer="$(call "$seat" eth_sendRawTransaction "[\"$tx\"]")"
  echo "$answer" | grep -q '"result"' || bad "transaction $sent to seat $seat: $answer"
  sent=$((sent + 1))
  sleep 2.5
done <"$TXS"

want=$(printf '0x%x' "$sent")
for _ in $(seq 1 60); do
  done_all=1
  for i in "${live[@]}"; do
    [[ "$(call "$i" eth_getTransactionCount "[\"$FROM\",\"latest\"]" | field result)" == "$want" ]] || done_all=0
  done
  [[ "$done_all" == 1 ]] && break
  sleep 1
done

height=$(( $(call "${live[0]}" eth_blockNumber | field result) ))
(( height > IMPORT )) && ok "the chain is at height $height after $sent transactions ($IMPORT imported)" \
  || bad "no block was built past height $IMPORT"
for i in "${live[@]}"; do
  n="$(call "$i" eth_getTransactionCount "[\"$FROM\",\"latest\"]" | field result)"
  [[ "$n" == "$want" ]] && ok "seat $i executed all $sent transactions" || bad "seat $i nonce $n, want $want"
done
for h in $(seq 1 "$height"); do
  hx=$(printf '0x%x' "$h")
  first=""
  for i in "${live[@]}"; do
    hash="$(call "$i" eth_getBlockByNumber "[\"$hx\",false]" | field hash)"
    [[ -z "$first" ]] && first="$hash"
    [[ -n "$hash" && "$hash" == "$first" ]] || bad "height $h: seat $i has '$hash', seat ${live[0]} has '$first'"
  done
done
(( fail == 0 )) && ok "every validator that is up accepted the same block at heights 1..$height"

echo "== who built each block (a slot is a window at the height; each is one proposer's)"
grep -h " led " "$TMP"/node*.log | sort -t' ' -k4,4n -u | sed 's/^/  /'

echo
if (( fail )); then echo "FAIL"; for i in "${live[@]}"; do echo "--- node $i"; tail -15 "$TMP/node$i.log"; done; exit 1; fi
if (( IMPORT > 0 )); then echo "PASS — ${#live[@]} of $N validators, one chain, continued from an export at $IMPORT"
else echo "PASS — ${#live[@]} of $N validators, one chain"; fi
