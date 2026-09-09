# Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Eco
#
# zood / luxd / noded — the C++ runtime, as an image.
#
# BUILD CONTEXT IS THE ORG DIRECTORY, NOT THIS REPO. CMakeLists reuses three
# checkouts rather than vendoring them — the consensus engine, cevm, and the
# luxcpp root that carries blst, cevm::crypto::bls and zap-cpp-core — and it
# looks for them beside this one. Build from the directory that holds them:
#
#     docker build -f node/Dockerfile -t ghcr.io/luxfi/lux-cpp-node .
#
# run from the lux-cpp checkout's parent, with luxcpp beside lux-cpp.
#
# THE BUILDER'S DEBIAN RELEASE IS THE RUNTIME'S, AND THAT IS LOAD-BEARING.
# A binary carries the symbol versions of the glibc it was linked against, and
# distroless-*-debian12 provides Debian 12's: glibc 2.36, GLIBCXX_3.4.30. Built
# anywhere newer, it builds, it pushes, and it dies on first exec with
# `version GLIBC_2.38 not found` — a failure that no build log shows. Measured,
# not assumed: a host-built binary was run against this base and did exactly
# that, and one built in bookworm ran.
#
# AWS-LC is built here rather than reused, because the TLS 1.3 + X25519MLKEM768
# peer handshake links it and a prebuilt tree is a machine's state, not a
# checkout's.

# ── builder ─────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git ca-certificates go-md2man golang-go perl \
        nlohmann-json3-dev python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# cevm resolves intx, blst and the rest through Conan. Without it CMake stops at
# the guard in CMakeLists.txt rather than failing 200 lines deep inside cevm's
# find_package — but stopping early is still stopping, and this image had no
# Conan at all, so it had never built.
RUN python3 -m venv /opt/conan && /opt/conan/bin/pip install --no-cache-dir 'conan>=2,<3'
ENV PATH=/opt/conan/bin:$PATH

WORKDIR /src
COPY luxcpp luxcpp
COPY lux-cpp/consensus lux-cpp/consensus
COPY lux-cpp/node lux-cpp/node

# AWS-LC, once, into its own tree.
ARG AWSLC_REF=v1.65.0
RUN git clone --depth 1 --branch ${AWSLC_REF} https://github.com/aws/aws-lc.git /src/aws-lc && \
    cmake -S /src/aws-lc -B /src/aws-lc-build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF && \
    cmake --build /src/aws-lc-build --target ssl crypto

# The node. Release, and stripped at link time rather than after: a symbol that
# is never emitted cannot be shipped by forgetting to remove it.
# The profile cevm publishes for this, so the toolchain the node is configured
# with is the one cevm's own CI uses.
# The lux packages are not on any Conan remote — they are the trees checked
# out beside this one, so they are exported from source before anything asks
# for them. Without this, `conan install` stops at
# "Package 'lux-crypto/1.4.5' not resolved".
# lux-crypto's deps are FetchContent clones of private luxcpp forks (intx,
# evmmax, pqclean, ed25519-donna, blake3-reference), so the configure step needs
# the same credential the checkouts used. It arrives as a build secret and is
# rewritten into a git URL prefix, which reaches every nested clone — including
# ones added later — rather than being named dep by dep. The rewrite lives in a
# file this one command owns, named by GIT_CONFIG_GLOBAL so only git reads it
# (HOME would move Conan's cache with it) and removed before the layer closes.
RUN --mount=type=secret,id=gh_pat \
    export GIT_CONFIG_GLOBAL=/tmp/gitcred && \
    git config --global url."https://x-access-token:$(cat /run/secrets/gh_pat)@github.com/".insteadOf "https://github.com/" && \
    conan profile detect --force && \
    for pkg in crypto blst zap-cpp-core; do \
        [ -f "/src/luxcpp/$pkg/conanfile.py" ] && conan export "/src/luxcpp/$pkg" || true; \
    done && \
    conan install /src/luxcpp/cevm \
      -pr /src/luxcpp/cevm/.github/conan/manylinux-relax.profile \
      -s build_type=Release -s compiler.cppstd=gnu20 \
      --output-folder=/src/cevm-conan --build=missing && \
    rm -f /tmp/gitcred

RUN cmake -S lux-cpp/node -B /src/build -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE=/src/cevm-conan/build/Release/generators/conan_toolchain.cmake \
      -DLUX_CEVM_DEX_U256_DIR=/src/lux-gpu/gpu-kernels/tools/kat \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_FLAGS_RELEASE="-O3 -DNDEBUG" \
        -DCMAKE_EXE_LINKER_FLAGS="-s" \
        -DCONSENSUS_DIR=/src/lux-cpp/consensus \
        -DCEVM_DIR=/src/luxcpp/cevm \
        -DLUXCPP_ROOT=/src/luxcpp \
        -DZAP_DIR=/src/luxcpp/zap-cpp-core/include \
        -DAWSLC_SRC=/src/aws-lc \
        -DAWSLC_BUILD_DIR=/src/aws-lc-build && \
    cmake --build /src/build --target luxd noded lux-join

RUN mkdir -p /out/bin /out/data && \
    cp /src/build/luxd /src/build/noded /src/build/lux-join /out/bin/ && \
    chown -R 65532:65532 /out

# ── runtime ─────────────────────────────────────────────────────────────────
# cc, not static: this binary is dynamically linked and `ldd build/zood` names
# libstdc++, libgcc_s, libm and libc — measured, not assumed. cc carries exactly
# those. It carries no shell, no package manager and no curl, so an image that
# holds a validator's key holds nothing that can be told to fetch and run.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /out/bin/ /usr/local/bin/
COPY --from=builder --chown=65532:65532 /out/data /data

USER nonroot
WORKDIR /data

# RPC, and the base port the vote mesh listens on.
EXPOSE 9730 9731

ENTRYPOINT ["/usr/local/bin/luxd"]
