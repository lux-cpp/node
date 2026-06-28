#!/usr/bin/env bash
# Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# cluster_5.sh — boot five node2d PROCESSES (not threads) into a full loopback
# TCP mesh and assert every one independently finalizes. This is the real
# multi-process companion to node2_cluster_test (which runs in one binary).
#
# Usage: scripts/cluster_5.sh [path-to-node2d] [base-port]
set -euo pipefail

NODE2D="${1:-build/node2d}"
BASE_PORT="${2:-19310}"
N=5

if [[ ! -x "$NODE2D" ]]; then
  echo "node2d not found/executable at: $NODE2D" >&2
  echo "build first:  cmake -S . -B build && cmake --build build -j" >&2
  exit 2
fi

TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT

echo "== launching $N node2d processes, base port $BASE_PORT =="
pids=()
for i in $(seq 0 $((N - 1))); do
  "$NODE2D" --index "$i" --n "$N" --base-port "$BASE_PORT" --deadline-ms 15000 \
      >"$TMP/node$i.log" 2>&1 &
  pids+=("$!")
done

rc=0
for i in $(seq 0 $((N - 1))); do
  if ! wait "${pids[$i]}"; then rc=1; fi
done

echo "== per-node output =="
final=0
for i in $(seq 0 $((N - 1))); do
  cat "$TMP/node$i.log"
  if grep -q "FINAL .*cert=VERIFIED" "$TMP/node$i.log"; then final=$((final + 1)); fi
done

echo "--------------------------------------------------------------"
if [[ "$final" -eq "$N" && "$rc" -eq 0 ]]; then
  echo "==== node2d CLUSTER (processes): PASS — $final/$N finalized over real TCP ===="
  exit 0
fi
echo "==== node2d CLUSTER (processes): FAIL — $final/$N finalized ===="
exit 1
