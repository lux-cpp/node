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
# Reused checkout layout (NOT vendored): ${LUXCPP_ROOT}/{consensus2-seed,zap-cpp-core,blst,crypto}.

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

# Locate the reused luxcpp assets (default: the parent of this dir).
get_filename_component(_default_luxcpp "${CMAKE_SOURCE_DIR}/.." ABSOLUTE)
set(LUXCPP_ROOT      "${_default_luxcpp}"                      CACHE PATH "luxcpp checkout root")
set(CONSENSUS2_DIR   "${LUXCPP_ROOT}/consensus2-seed"          CACHE PATH "consensus2 seed source dir")
set(ZAP_DIR          "${LUXCPP_ROOT}/zap-cpp-core/include"     CACHE PATH "zap-cpp-core include root")

foreach(_p "${CONSENSUS2_DIR}/CMakeLists.txt" "${ZAP_DIR}/lux/zap/wire.hpp")
  if(NOT EXISTS "${_p}")
    message(FATAL_ERROR "node2: required reused asset not found: ${_p}\n"
                        "set -DLUXCPP_ROOT=/path/to/luxcpp")
  endif()
endforeach()

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

# ── tests
enable_testing()

add_executable(frame_reader_test test/frame_reader_test.cpp)
target_link_libraries(frame_reader_test PRIVATE node2)
target_compile_options(frame_reader_test PRIVATE -Wall -Wextra)
add_test(NAME frame_reader COMMAND frame_reader_test)

add_executable(node2_cluster_test test/node2_cluster_test.cpp)
target_link_libraries(node2_cluster_test PRIVATE node2)
target_compile_options(node2_cluster_test PRIVATE -Wall -Wextra)
add_test(NAME node2_cluster COMMAND node2_cluster_test)

# over-the-wire liveness: down + wedged-but-present validators routed around
add_executable(node2_liveness_test test/node2_liveness_test.cpp)
target_link_libraries(node2_liveness_test PRIVATE node2)
target_compile_options(node2_liveness_test PRIVATE -Wall -Wextra)
add_test(NAME node2_liveness COMMAND node2_liveness_test)

# fault-boundary robustness: closed-peer SIGPIPE, oversize-frame buffer bound, accept deadline
add_executable(node2_robustness_test test/node2_robustness_test.cpp)
target_link_libraries(node2_robustness_test PRIVATE node2)
target_compile_options(node2_robustness_test PRIVATE -Wall -Wextra)
add_test(NAME node2_robustness COMMAND node2_robustness_test)

# Apply NODE2_SANITIZE to node2's own targets only (the consensus2 subdir scopes
# its own; blst/bls stay clean). One place for the whole node2 surface.
if (NODE2_SANITIZE)
    set(_n2_san -fsanitize=${NODE2_SANITIZE} -fno-omit-frame-pointer)
    foreach(_t node2 node2d frame_reader_test node2_cluster_test node2_liveness_test node2_robustness_test)
        target_compile_options(${_t} PRIVATE ${_n2_san})
        target_link_options(${_t} PRIVATE ${_n2_san})
    endforeach()
endif()
