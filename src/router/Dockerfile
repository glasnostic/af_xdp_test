# --------------------- BASE LAYER ------------------------
FROM golang:1.12 AS base-layer
LABEL maintainer="guesslin@glasnostic.com"

# Install dependency
# pkg-config for cgo pkg-config
# curl for fetch codes
# bsdtar is from https://github.com/coreos/bugs/issues/1095
RUN apt-get update -qq && \
    apt-get install -y pkg-config curl cmake patch git unzip clang llvm libelf-dev kmod linux-base libssl-dev bison flex libncurses-dev bc zlib1g-dev libpcap-dev && \
    apt-get install -y --no-install-recommends bsdtar

# Prepare kernel and compile/install libbpf
ARG kernel_version=5.1
RUN cd /usr/src && \
    wget -c https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${kernel_version}.tar.xz && \
    bsdtar xJf linux-${kernel_version}.tar.xz && \
    cd linux-${kernel_version} && \
    make defconfig && \
    make modules_prepare

# Adoptation for different networkdriver
ARG libbpf_version=v0.0.3
RUN cd /tmp/ && git clone -b ${libbpf_version} --single-branch --depth=1 https://github.com/libbpf/libbpf.git && \
    cd libbpf/src && make && \
    BUILD_STATIC_ONLY=y OBJDIR=/lib/x86_64-linux-gnu/ make install && \
    mkdir -p /usr/include/uapi/linux/ && \
    cd /tmp/libbpf/ && \
    cp include/uapi/linux/* /usr/include/uapi/linux/ && \
    cp /usr/include/uapi/linux/if_link.h /usr/include/linux && \
    cp /usr/include/uapi/linux/bpf.h /usr/include/linux/

# -------------------- BUILDER -----------------------
FROM base-layer AS builder

# build folder
RUN mkdir -p /go/router
WORKDIR /go/router

# cache go module file
COPY go.mod .
COPY go.sum .
RUN go mod download
# copy codes
COPY . .
RUN go generate ./...
RUN go build -o router

# --------------------- FINAL LAYER -----------------------
FROM golang:1.12 AS final-layer
LABEL maintainer="guesslin@glasnostic.com"

RUN apt-get update && \
    apt-get install -y libpcap0.8 ethtool iptables && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /go/bin/
COPY --from=builder /go/router/router /go/bin/
COPY ./docker-entrypoint.sh /go/bin/

ENTRYPOINT ["/go/bin/docker-entrypoint.sh"]
