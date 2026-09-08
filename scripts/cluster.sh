#!/usr/bin/env bash
# Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# cluster.sh — boot noded PROCESSES (not threads) into a loopback TCP mesh and
# assert that every process that should finalize does. The real multi-process
# companion to node_cluster_test (which runs in one binary).
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
# THE PROPOSER IS ROUND-ROBIN AND THERE IS NO FAILOVER: height h is led by
# validator h mod n and by nobody else, so the height a held-down validator
# leads is a height this cluster does not decide. Hold down a validator whose
# turn falls beyond this run (i >= BLOCKS, or i == 0) — measured, not assumed:
# `cluster.sh build/noded PORT 5 1` stops every node at height 1, which is the
# height validator 1 leads.
#
# Every process is handed the SAME committee file and the SAME peer list — the
# description a real operator writes. Each validator's keys are made once, here,
# and each publishes the line the file is assembled from; nothing is derived
# from an index.
#
# Usage: scripts/cluster.sh [noded] [base-port] [n] [down-index]
set -euo pipefail

NODED="${1:-build/noded}"
BASE_PORT="${2:-19310}"
N="${3:-5}"
DOWN="${4:--1}"
BLOCKS=3

if [[ ! -x "$NODED" ]]; then
  echo "noded not found/executable at: $NODED" >&2
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

# The network, written down once: every validator publishes a line, and the
# peer list is positional against it. The held-down validator is IN the
# committee — that is the case being tested.
peers=""
for i in $(seq 0 $((N - 1))); do
  "$NODED" --data "$TMP/v$i" --publish >>"$TMP/committee.txt"
  peers="${peers:+$peers,}127.0.0.1:$((BASE_PORT + i))"
done

echo "== launching $want of $N noded processes, base port $BASE_PORT${DOWN:+, validator $DOWN held down} =="
pids=()
for i in "${running[@]}"; do
  "$NODED" --data "$TMP/v$i" --committee "$TMP/committee.txt" --peers "$peers" \
      --blocks "$BLOCKS" --deadline-ms 5000 >"$TMP/node$i.log" 2>&1 &
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
  # Every running validator carried the last height to a certificate: a decided
  # block is the only thing that prints this line.
  if grep -q "block $BLOCKS .*voters" "$TMP/node$i.log"; then final=$((final + 1)); fi
done

echo "--------------------------------------------------------------"
if [[ "$final" -eq "$want" && "$rc" -eq 0 ]]; then
  echo "==== noded CLUSTER (processes): PASS — $final/$want decided height $BLOCKS over real TCP ===="
  exit 0
fi
echo "==== noded CLUSTER (processes): FAIL — $final/$want finalized ===="
exit 1
