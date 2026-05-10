# --- Stage 1. Builds DIE.

FROM i386/alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    qt5-qtbase-dev \
    qt5-qtscript-dev \
    qt5-qttools-dev \
    qt5-qtsvg-dev \
    pkgconfig \
    git \
    make \
    bash

# Clones latest DIE
RUN git clone --recursive --branch 3.21 https://github.com/horsicq/DIE-engine.git

WORKDIR /DIE-engine

# Initialize the build environment
RUN cp -f build_tools/build.pri .

# Build the engine
RUN qmake die_source.pro "DEFINES+=QT_NO_DEBUG_OUTPUT" && \
    make -j$(nproc)

# Strip symbols
RUN strip build/release/diec

# Copy the binary
RUN mkdir /build && \
    cp build/release/diec /build

# Use ldd to find all dependencies and copy them to /build
RUN ldd build/release/diec | grep "=> /" | awk '{print $3}' | xargs -I {} cp -v {} /build

# Copy database
RUN cp -r Detect-It-Easy/db /build

COPY scripts/run_diec.sh /build

# --- Stage 2. Builds Buildroot.

FROM debian:bullseye AS buildroot

# Copy v86 buildroot board config into image
COPY ./buildroot-v86 /buildroot-v86
COPY --from=builder /build /buildroot-v86/board/v86/rootfs_overlay/die_build

# Copy ld-musl-i386.so.1 to /lib
COPY --from=builder /build/ld-musl-i386.so.1 /buildroot-v86/board/v86/rootfs_overlay/lib/ld-musl-i386.so.1

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get -y install bc build-essential bzr cpio cvs git unzip wget libc6:i386 libncurses5-dev libssl-dev rsync file && \
    wget -c https://github.com/buildroot/buildroot/archive/refs/tags/2025.11.tar.gz && \
    tar axf 2025.11.tar.gz && \
    mv /buildroot-2025.11 /buildroot

ENV FORCE_UNSAFE_CONFIGURE=1

# Builds Buildroot, licenses, and caches some directories
WORKDIR /buildroot
RUN --mount=type=cache,target=/root/.buildroot-ccache \
    --mount=type=cache,target=/buildroot/dl \
    set -e; \
    make BR2_EXTERNAL=/buildroot-v86 v86_defconfig && \
    make legal-info && \
    make -j$(nproc) && \
    mkdir licenses && \
    cp -r output/legal-info/host-licenses/ output/legal-info/licenses/ output/legal-info/buildroot.config licenses && \
    cp -r output/images /build && \
    tar -czf /build/licenses.tar.gz licenses

# --- Stage 3. Builds initial state.

FROM node:bullseye AS initial-state

WORKDIR /v86

RUN wget -c https://github.com/copy/v86/releases/download/latest/v86.wasm && \
    wget -c https://github.com/copy/v86/releases/download/latest/libv86.js && \
    wget -c https://github.com/copy/v86/raw/refs/heads/master/bios/seabios.bin

COPY --from=buildroot /build/rootfs.cpio /build/bzImage /build/licenses.tar.gz /v86

RUN apt-get update && \
    apt-get install -y zstd && \
    gzip rootfs.cpio

# Builds initial state
COPY scripts/nodejs_state.js /v86

# Compresses initial state
RUN node nodejs_state.js && \
    zstd -19 buildroot-state.bin && \
    rm rootfs.cpio.gz bzImage buildroot-state.bin nodejs_state.js

# --- Stage 4. Exports compressed initial state.

FROM scratch AS export
COPY --from=initial-state /v86 .
