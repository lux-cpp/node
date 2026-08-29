# Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# node2 — a running consensus2 node: the consensus2 engine + a ZAP vote mesh over
# real TCP sockets. Layering (each layer below is REUSED unmodified):
#
#   blst → bls_signature (cevm::crypto::bls) → consensus2 (the gate + Node)
#     [all three built by consensus2-seed/CMakeLists, added as a subdirectory]
#   lux::zap wire codec (zap-cpp-core, header-only)
#     ──────────────────────── NEW in node2 ────────────────────────
#   FrameReader (non-blocking reassembler, header-only)
#   MeshVoteTransport (VoteTransport over N TCP sockets, header-only)
#   Node2Host (listen/accept/dial mesh + drive the Node)   ← the one .cpp
#
# Reused, NOT vendored: the consensus2 checkout (the engine) and the luxcpp
# checkout (blst, cevm::crypto::bls, zap-cpp-core). Both are found automatically
# where they actually sit; -DCONSENSUS2_DIR / -DLUXCPP_ROOT override.

cmake_minimum_required(VERSION 3.20)
project(node2 LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Sanitizer for node2's + consensus2's OWN code (NOT the reused blst/bls assembly
# crypto). TSan here is load-bearing: the mesh setup is multi-threaded and the gate
# mutex is exercised across threads. Usage: -DNODE2_SANITIZE=thread  (or address,undefined)
set(NODE2_SANITIZE "" CACHE STRING "Sanitizer for node2+consensus2 code (e.g. thread | address,undefined)")
# Propagate to the consensus2 subdir so the reused gate is instrumented to match,
# while blst/bls_signature stay clean (consensus2 scopes it the same way).
if (NODE2_SANITIZE AND NOT CONSENSUS2_SANITIZE)
  set(CONSENSUS2_SANITIZE "${NODE2_SANITIZE}" CACHE STRING "" FORCE)
endif()

# find_checkout(VAR MARKER candidate...) — first candidate holding MARKER wins.
# One search, used for both reused trees, so "where does X live" is stated once.
function(find_checkout out marker)
  foreach(_root ${ARGN})
    get_filename_component(_abs "${_root}" ABSOLUTE)
    if(EXISTS "${_abs}/${marker}")
      set(${out} "${_abs}" PARENT_SCOPE)
      return()
    endif()
  endforeach()
  set(${out} "${out}-NOTFOUND" PARENT_SCOPE)
endfunction()

# consensus2 — sibling of node2 in the lux checkout, or inside a luxcpp checkout.
find_checkout(_consensus2 "include/lux/consensus2/node.hpp"
  "${CMAKE_SOURCE_DIR}/../consensus2"
  "${CMAKE_SOURCE_DIR}/../../luxcpp/consensus2"
  "${CMAKE_SOURCE_DIR}/../luxcpp/consensus2")

# luxcpp — blst + cevm::crypto::bls + zap-cpp-core all live under one root.
find_checkout(_luxcpp "blst/bindings/blst.h"
  "${CMAKE_SOURCE_DIR}/../../luxcpp"
  "${CMAKE_SOURCE_DIR}/../luxcpp"
  "${CMAKE_SOURCE_DIR}/..")

set(CONSENSUS2_DIR "${_consensus2}"                    CACHE PATH "consensus2 checkout")
set(LUXCPP_ROOT    "${_luxcpp}"                        CACHE PATH "luxcpp checkout root")
set(ZAP_DIR        "${LUXCPP_ROOT}/zap-cpp-core/include" CACHE PATH "zap-cpp-core include root")

foreach(_p "${CONSENSUS2_DIR}/CMakeLists.txt"
           "${ZAP_DIR}/lux/zap/wire.hpp"
           "${LUXCPP_ROOT}/blst/bindings/blst.h"
           "${LUXCPP_ROOT}/crypto/bls/cpp/bls_signature.cpp")
  if(NOT EXISTS "${_p}")
    message(FATAL_ERROR "node2: required reused asset not found: ${_p}\n"
                        "searched for consensus2 and luxcpp beside this checkout; "
                        "set -DCONSENSUS2_DIR=/path/to/consensus2 -DLUXCPP_ROOT=/path/to/luxcpp")
  endif()
endforeach()
message(STATUS "node2: consensus2 = ${CONSENSUS2_DIR}")
message(STATUS "node2: luxcpp     = ${LUXCPP_ROOT}")

find_package(Threads REQUIRED)

# ── Reuse consensus2-seed's build (brings the blst / bls_signature / consensus2
#    targets with correct include + link propagation). One build definition for
#    the reused layers — no duplication here.
add_subdirectory("${CONSENSUS2_DIR}" consensus2-build)

# ── node2 — the NEW host library (the only compiled unit; the rest is header-only)
add_library(node2 STATIC src/node2_host.cpp)
target_include_directories(node2 PUBLIC include "${ZAP_DIR}")
target_link_libraries(node2 PUBLIC consensus2 Threads::Threads)
target_compile_options(node2 PRIVATE -Wall -Wextra -Wpedantic)

# ── node2d — the standalone daemon process
add_executable(node2d src/node2d.cpp)
target_link_libraries(node2d PRIVATE node2)
target_compile_options(node2d PRIVATE -Wall -Wextra)

# ── tests — one registration, one list
#   frame_reader    the reassembler in isolation (fragmentation, batching, limits)
#   mesh_transport  what one hostile or dead socket can do to this node
#   mesh_formation  mesh setup is bounded, and a missing validator is not a dead cluster
#   node2_cluster   five hosts finalize over a real loopback mesh
#   node2_liveness  down + wedged-but-present validators routed around, on the wire
enable_testing()

set(NODE2_TESTS frame_reader mesh_transport mesh_formation node2_cluster node2_liveness)
foreach(_t ${NODE2_TESTS})
    add_executable(${_t}_test test/${_t}_test.cpp)
    target_link_libraries(${_t}_test PRIVATE node2)
    target_compile_options(${_t}_test PRIVATE -Wall -Wextra)
    add_test(NAME ${_t} COMMAND ${_t}_test)
endforeach()

# Apply NODE2_SANITIZE to node2's own targets only (the consensus2 subdir scopes
# its own; blst/bls stay clean). One place for the whole node2 surface.
if (NODE2_SANITIZE)
    set(_n2_san -fsanitize=${NODE2_SANITIZE} -fno-omit-frame-pointer)
    set(_n2_targets node2 node2d)
    foreach(_t ${NODE2_TESTS})
        list(APPEND _n2_targets ${_t}_test)
    endforeach()
    foreach(_t ${_n2_targets})
        target_compile_options(${_t} PRIVATE ${_n2_san})
        target_link_options(${_t} PRIVATE ${_n2_san})
    endforeach()
endif()
