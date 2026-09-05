# Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# node — a running consensus node: the consensus engine + a ZAP vote mesh over
# real TCP sockets. Layering (each layer below is REUSED unmodified):
#
#   blst → bls_signature → consensus (the gate + Node, and its BLS domain)
#     [all built by the consensus checkout's CMakeLists, added as a subdirectory]
#   lux::zap wire codec (zap-cpp-core, header-only)
#     ──────────────────────── NEW in node ────────────────────────
#   FrameReader (non-blocking reassembler, header-only)
#   MeshVoteTransport (VoteTransport over N TCP sockets, header-only)
#   Node2Host (listen/accept/dial mesh + drive the Node)   ← the one .cpp
#
# Reused, NOT vendored: the consensus checkout (the engine) and the luxcpp
# checkout (blst, cevm::crypto::bls, zap-cpp-core). Both are found automatically
# where they actually sit; -DCONSENSUS_DIR / -DLUXCPP_ROOT override.

cmake_minimum_required(VERSION 3.20)
project(node LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Sanitizer for node's + consensus's OWN code (NOT the reused blst/bls assembly
# crypto). TSan here is load-bearing: the mesh setup is multi-threaded and the gate
# mutex is exercised across threads. Usage: -DNODE_SANITIZE=thread  (or address,undefined)
set(NODE_SANITIZE "" CACHE STRING "Sanitizer for node+consensus code (e.g. thread | address,undefined)")
# Propagate to the consensus subdir so the reused gate is instrumented to match,
# while blst/bls_signature stay clean (consensus scopes it the same way).
if (NODE_SANITIZE AND NOT CONSENSUS_SANITIZE)
  set(CONSENSUS_SANITIZE "${NODE_SANITIZE}" CACHE STRING "" FORCE)
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

# consensus — the C++ consensus lives in the luxcpp checkout, so look there first.
# The sibling candidate stays for a side-by-side checkout, but it is LAST and it is
# why the marker is a header rather than a directory name: beside node in the lux
# checkout sits luxfi/consensus, the GO implementation, under the very same name.
# Matching on include/lux/consensus/node.hpp is what tells the two apart.
find_checkout(_consensus "include/lux/consensus/node.hpp"
  "${CMAKE_SOURCE_DIR}/../../luxcpp/consensus"
  "${CMAKE_SOURCE_DIR}/../luxcpp/consensus"
  "${CMAKE_SOURCE_DIR}/../consensus")

# cevm — the C++ EVM that executes the C-Chain's blocks. Found the same way the
# other reused trees are, and matched on a source file rather than the directory
# name for the same reason: `cevm` is also the name of a Go binding and of a
# Conan package. lib/evm/state/processor.hpp is what identifies the checkout.
find_checkout(_cevm "lib/evm/state/processor.hpp"
  "${CMAKE_SOURCE_DIR}/../cevm"
  "${CMAKE_SOURCE_DIR}/../../luxcpp/cevm"
  "${CMAKE_SOURCE_DIR}/../luxcpp/cevm")

# luxcpp — blst + cevm::crypto::bls + zap-cpp-core all live under one root.
find_checkout(_luxcpp "blst/bindings/blst.h"
  "${CMAKE_SOURCE_DIR}/../../luxcpp"
  "${CMAKE_SOURCE_DIR}/../luxcpp"
  "${CMAKE_SOURCE_DIR}/..")

set(CONSENSUS_DIR "${_consensus}"                    CACHE PATH "consensus checkout")
set(CEVM_DIR       "${_cevm}"                          CACHE PATH "cevm checkout")
set(LUXCPP_ROOT    "${_luxcpp}"                        CACHE PATH "luxcpp checkout root")
set(ZAP_DIR        "${LUXCPP_ROOT}/zap-cpp-core/include" CACHE PATH "zap-cpp-core include root")

foreach(_p "${CONSENSUS_DIR}/CMakeLists.txt"
           "${CEVM_DIR}/lib/evm/state/processor.hpp"
           "${ZAP_DIR}/lux/zap/wire.hpp"
           "${LUXCPP_ROOT}/blst/bindings/blst.h"
           "${LUXCPP_ROOT}/crypto/bls/cpp/bls_signature.cpp")
  if(NOT EXISTS "${_p}")
    message(FATAL_ERROR "node: required reused asset not found: ${_p}\n"
                        "searched for consensus and luxcpp beside this checkout; "
                        "set -DCONSENSUS_DIR=/path/to/consensus -DLUXCPP_ROOT=/path/to/luxcpp")
  endif()
endforeach()
message(STATUS "node: consensus = ${CONSENSUS_DIR}")
message(STATUS "node: luxcpp     = ${LUXCPP_ROOT}")
message(STATUS "node: cevm       = ${CEVM_DIR}")

# cevm's dependencies (intx, nlohmann_json, lux-crypto, bls, lux-zap-core) come
# from Conan, so node is configured with the toolchain Conan generated for it.
# Saying so here — rather than failing 200 lines later inside cevm's
# find_package(intx) — is the difference between a build you can fix and one you
# have to bisect.
if(NOT TARGET intx::intx AND NOT CMAKE_TOOLCHAIN_FILE)
  message(FATAL_ERROR
    "node: cevm's dependencies come from Conan and no toolchain was given.\n"
    "  conan install ${CEVM_DIR} -pr ${CEVM_DIR}/.github/conan/manylinux-relax.profile \\\n"
    "    -s build_type=Release -s compiler.cppstd=gnu20 \\\n"
    "    --output-folder=${CEVM_DIR}/build-node --build=missing\n"
    "  cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=${CEVM_DIR}/build-node/build/Release/generators/conan_toolchain.cmake")
endif()

find_package(Threads REQUIRED)

# ── AWS-LC — the ONLY TLS stack on this machine offering luxd's mandatory
#    X25519MLKEM768 hybrid group (`network/peer/tls_config.go`'s single-
#    element CurvePreferences list). System OpenSSL here is 3.0.13, which
#    predates the group entirely; AWS-LC 0.45.0 (the exact version node.rs's
#    own `aws-lc-rs` dependency resolves to) has it at the SAME wire codepoint
#    Go's crypto/tls assigns (`SSL_GROUP_X25519_MLKEM768 = 0x11EC`). Built
#    standalone from its own CMakeLists (its source ships inside the
#    `aws-lc-sys` crate; this repo depends on neither Cargo nor that crate,
#    only on the C library it vendors) — see LLM.md for the exact command.
#    Not a Conan package: nothing in this stack packages it.
#    Found the way the other two reused trees are found, rather than named on
#    the command line: it is a checkout beside them and it was the one
#    dependency that made configuring this repo a two-step job. -DAWSLC_SRC
#    and -DAWSLC_BUILD_DIR still override.
set(AWSLC_SRC       "" CACHE PATH "AWS-LC source tree (has include/openssl/ssl.h)")
set(AWSLC_BUILD_DIR "" CACHE PATH "AWS-LC build dir (has crypto/libcrypto.a, ssl/libssl.a)")
if(NOT AWSLC_SRC)
  find_checkout(AWSLC_SRC "include/openssl/ssl.h"
    "${CMAKE_SOURCE_DIR}/../aws-lc"
    "${CMAKE_SOURCE_DIR}/../../luxcpp/aws-lc"
    "${CMAKE_SOURCE_DIR}/../luxcpp/aws-lc")
endif()
if(NOT AWSLC_BUILD_DIR AND AWSLC_SRC)
  # The build is a directory under the source, and it counts only if the
  # library is actually in it: a configured-but-unbuilt tree is not an answer.
  find_checkout(AWSLC_BUILD_DIR "ssl/libssl.a"
    "${AWSLC_SRC}/build"
    "${AWSLC_SRC}/build/Release")
endif()
if(NOT AWSLC_SRC OR NOT EXISTS "${AWSLC_SRC}/include/openssl/ssl.h" OR
   NOT AWSLC_BUILD_DIR OR NOT EXISTS "${AWSLC_BUILD_DIR}/ssl/libssl.a")
  message(FATAL_ERROR
    "node: AWS-LC not found. Build it once — see LLM.md \"Building AWS-LC\" —\n"
    "then pass -DAWSLC_SRC=<...>/aws-lc -DAWSLC_BUILD_DIR=<build dir>.")
endif()
message(STATUS "node: aws-lc      = ${AWSLC_BUILD_DIR}")
add_library(awslc_crypto STATIC IMPORTED)
set_target_properties(awslc_crypto PROPERTIES IMPORTED_LOCATION "${AWSLC_BUILD_DIR}/crypto/libcrypto.a")
add_library(awslc_ssl STATIC IMPORTED)
set_target_properties(awslc_ssl PROPERTIES
  IMPORTED_LOCATION "${AWSLC_BUILD_DIR}/ssl/libssl.a"
  INTERFACE_LINK_LIBRARIES awslc_crypto
  INTERFACE_INCLUDE_DIRECTORIES "${AWSLC_SRC}/include")

# ── Reuse consensus's build (brings the blst / bls_signature / consensus targets
#    with correct include + link propagation). One build definition for the reused
#    layers — no duplication here.
add_subdirectory("${CONSENSUS_DIR}" consensus-build)

# ── Reuse cevm's build the same way. EXCLUDE_FROM_ALL because node links four of
#    its libraries and does not want its 40-odd test and benchmark binaries; they
#    stay buildable by name. Static, because noded is one process: cevm defaults
#    to a shared library so it can be loaded as an EVMC plugin, which is not how
#    it is used here.
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CEVM_TESTING      OFF CACHE BOOL "" FORCE)
add_subdirectory("${CEVM_DIR}" cevm-build EXCLUDE_FROM_ALL)

# ── node — the NEW host library (the only compiled unit; the rest is header-only)
add_library(node STATIC
    src/mesh.cpp          # the socket dance
    src/node_host.cpp     # one Party driven over that mesh
    src/engine.cpp        # execute → decide → accept, for any VM
    src/evm.cpp           # the C-Chain, executed by cevm
    src/import.cpp        # the C-chain's external format, read back
    src/rpc.cpp           # HTTP JSON-RPC
    src/eth.cpp           # the eth methods, mounted on an Rpc
    src/validators.cpp    # the set-root commitment a vote binds
    src/staking.cpp        # a luxd peer's identity: P-256 cert + NodeID + BLS
    src/peer_tls.cpp       # TLS 1.3 + X25519MLKEM768, over AWS-LC
    src/peer.cpp)          # the p2p Handshake/PushQuery/vote path to a live luxd
target_include_directories(node PUBLIC include "${ZAP_DIR}")
target_link_libraries(node PUBLIC consensus Threads::Threads awslc_ssl)
# evm-state carries the StateDB, process_block and the Merkle-Patricia-Trie; evm
# is the interpreter behind evmc_create_cevm. lux::crypto-secp256k1 is what
# recovers a transaction's sender, and nlohmann_json is the RPC's codec.
# find_package again at THIS level, not because cevm forgot to: an imported
# target a subdirectory creates is scoped to that subdirectory, so node has to
# ask for the two it links by name itself. Same packages, same Conan-generated
# configs, resolved a second time — not a second source of truth.
find_package(crypto CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(node PUBLIC evm-state evm lux::crypto-secp256k1 lux::crypto-sha256 nlohmann_json::nlohmann_json)
target_compile_options(node PRIVATE -Wall -Wextra -Wpedantic)

# ── luxd — the standalone daemon process (C++ version)
add_executable(luxd src/noded.cpp)
target_link_libraries(luxd PRIVATE node)
target_compile_options(luxd PRIVATE -Wall -Wextra)

# ── zood — Zoo L2 flavor (C++ version)
add_executable(zood src/noded.cpp)
target_link_libraries(zood PRIVATE node)
target_compile_options(zood PRIVATE -Wall -Wextra)

# ── noded — backwards-compatible alias
add_executable(noded src/noded.cpp)
target_link_libraries(noded PRIVATE node)
target_compile_options(noded PRIVATE -Wall -Wextra)

# ── lux-join — a validator on a REAL, external luxd network (not this node's
#   own self-referential mesh): PQ-gated TLS, the p2p Handshake, and a signed
#   Quasar vote on whatever luxd proposes. See LLM.md.
add_executable(lux-join src/lux_join_main.cpp)
target_link_libraries(lux-join PRIVATE node)
target_compile_options(lux-join PRIVATE -Wall -Wextra)

# ── tests — one registration, one list
#   frame_reader    the reassembler in isolation (fragmentation, batching, limits)
#   wire_vector     the bytes on the wire, written from the spec and read off a socket
#   mesh_transport  what one hostile or dead socket can do to this node
#   mesh_formation  mesh setup is bounded, and a missing validator is not a dead cluster
#   node_cluster   five hosts finalize over a real loopback mesh
#   node_liveness  down + wedged-but-present validators routed around, on the wire
#   boot_floor      a restarted validator does not re-sign a height it decided
#   hostile_decode  what a stranger can send the two decoders that take his bytes
#   set_root        the validator-set commitment, against Go's encoding
#   chain_route     every spelling of a chain's path reaches that one chain
#   archive_proxy   what a relayed answer's status is, when this node is a proxy
#   block_reject    a block that is not accepted gives its transactions back
#   import          the canonical RLP export, walked block by block, and the
#                   refusal that follows a tip nobody here decided
enable_testing()

set(NODE_TESTS frame_reader wire_vector mesh_transport mesh_formation node_cluster node_liveness boot_floor hostile_decode set_root chain_route archive_proxy block_reject import)
foreach(_t ${NODE_TESTS})
    add_executable(${_t}_test test/${_t}_test.cpp)
    target_link_libraries(${_t}_test PRIVATE node)
    target_compile_options(${_t}_test PRIVATE -Wall -Wextra)
    add_test(NAME ${_t} COMMAND ${_t}_test)
endforeach()

# Apply NODE_SANITIZE to node's own targets only (the consensus subdir scopes
# its own; blst/bls stay clean). One place for the whole node surface.
if (NODE_SANITIZE)
    set(_n2_san -fsanitize=${NODE_SANITIZE} -fno-omit-frame-pointer)
    set(_n2_targets node noded)
    foreach(_t ${NODE_TESTS})
        list(APPEND _n2_targets ${_t}_test)
    endforeach()
    foreach(_t ${_n2_targets})
        target_compile_options(${_t} PRIVATE ${_n2_san})
        target_link_options(${_t} PRIVATE ${_n2_san})
    endforeach()
endif()
