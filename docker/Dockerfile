# Build from the repository root so the local tree is copied in:
#   docker build -f docker/Dockerfile -t idfuzz .
# If proxy.golang.org or go.dev is unreachable, pass mirrors, e.g.
#   --build-arg GOPROXY=https://goproxy.cn,direct --build-arg GO_DL_BASE=https://golang.google.cn/dl
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    sudo \
    build-essential \
    cmake \
    git \
    wget \
    curl \
    vim \
    python3.8 \
    python3-pip \
    python3-dev \
    llvm-10 \
    clang-10 \
    llvm-10-dev \
    llvm-10-tools \
    libc++-10-dev \
    libc++abi-10-dev \
    automake \
    autoconf \
    libtool \
    pkg-config \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    zlib1g-dev \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-10 100 && \
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-10 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-10 100 && \
    update-alternatives --install /usr/bin/opt opt /usr/bin/opt-10 100 && \
    update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-10 100 && \
    update-alternatives --install /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-10 100 && \
    update-alternatives --install /usr/bin/llvm-dis llvm-dis /usr/bin/llvm-dis-10 100

# Pinned to the last releases that support Python 3.8. torch is the CPU build.
RUN python3 -m pip install --no-cache-dir pip==24.0 && \
    python3 -m pip install --no-cache-dir \
    numpy==1.24.4 \
    networkx==3.1 \
    pydot==1.4.2 \
    pyparsing==2.4.7 \
    scikit-learn==1.3.2 \
    sysv_ipc==1.1.0 && \
    python3 -m pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.4.1

# gllvm (gclang/get-bc) extracts target.bc. Ubuntu 20.04's Go is too old to install it.
ARG GO_VERSION=1.21.13
ARG GO_SHA256=502fc16d5910562461e6a6631fb6377de2322aad7304bf2bcd23500ba9dab4a7
ARG GLLVM_VERSION=v1.3.1
ARG GOPROXY=https://proxy.golang.org,direct
ARG GO_DL_BASE=https://go.dev/dl
RUN curl -fsSL "${GO_DL_BASE}/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz && \
    echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c - && \
    tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz && \
    GOPROXY="${GOPROXY}" GOBIN=/usr/local/bin /usr/local/go/bin/go install "github.com/SRI-CSL/gllvm/cmd/...@${GLLVM_VERSION}" && \
    rm -rf /root/go /root/.cache/go-build

ENV IDFUZZ=/IDFuzz
COPY . ${IDFUZZ}
WORKDIR ${IDFUZZ}
RUN ./build.sh

CMD ["/bin/bash"]
