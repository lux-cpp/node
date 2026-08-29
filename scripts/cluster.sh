#!/usr/bin/env bash
# Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# cluster.sh — boot node2d PROCESSES (not threads) into a loopback TCP mesh and
# assert that every process that should finalize does. The real multi-process
# companion to node2_cluster_test (which runs in one binary).
#
# The optional DOWN index holds one validator back while every running process is
# still configured with the full set — the case a threads-in-one-binary test
# cannot reach, and the one where a mesh that demands every peer deadlocks a
# cluster whose remaining stake clears the ⅔ floor.
#
# A node with an absent validator waits out the mesh window before starting
# consensus — it cannot tell "not started yet" from "not coming". Loopback
# processes are up in milliseconds, so the window here is 5 s, not the daemon's
# 15 s default.
#
# Usage: scripts/cluster.sh [node2d] [base-port] [n] [down-index]
set -euo pipefail

NODE2D="${1:-build/node2d}"
BASE_PORT="${2:-19310}"
N="${3:-5}"
DOWN="${4:--1}"

if [[ ! -x "$NODE2D" ]]; then
  echo "node2d not found/executable at: $NODE2D" >&2
  echo "build first:  cmake -S . -B build && cmake --build build -j" >&2
  exit 2
fi

TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT

running=()
for i in $(seq 0 $((N - 1))); do
  [[ "$i" == "$DOWN" ]] && continue
  running+=("$i")
done
want="${#running[@]}"

echo "== launching $want of $N node2d processes, base port $BASE_PORT${DOWN:+, validator $DOWN held down} =="
pids=()
for i in "${running[@]}"; do
  "$NODE2D" --index "$i" --n "$N" --base-port "$BASE_PORT" --deadline-ms 5000 \
      >"$TMP/node$i.log" 2>&1 &
  pids+=("$!")
done

rc=0
for p in "${pids[@]}"; do
  if ! wait "$p"; then rc=1; fi
done

echo "== per-node output =="
final=0
for i in "${running[@]}"; do
  cat "$TMP/node$i.log"
  if grep -q "FINAL .*cert=VERIFIED" "$TMP/node$i.log"; then final=$((final + 1)); fi
done

echo "--------------------------------------------------------------"
if [[ "$final" -eq "$want" && "$rc" -eq 0 ]]; then
  echo "==== node2d CLUSTER (processes): PASS — $final/$want finalized over real TCP ===="
  exit 0
fi
echo "==== node2d CLUSTER (processes): FAIL — $final/$want finalized ===="
exit 1
