FROM debian:12 AS build

# Requirements
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    libssl-dev \
    crossbuild-essential-arm64 \
    gcc-aarch64-linux-gnu \
    qemu-user-static \
    git \
    wget \
    python3 \
    gawk \
    bison \
    libc6-dev-arm64-cross \
    flex \
    libtool \
    texinfo \
    autopoint \
    libncurses5-dev \
    gperf \
    gettext \
    make

RUN mkdir -p /app/
