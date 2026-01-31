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
    update-alternatives --install /usr/bin/opt opt /usr/bin/opt-10 100

RUN pip3 install --no-cache-dir \
    pwn \
    networkx \
    numpy \
    matplotlib \
    pydot==1.4.2 \
    torch \
    scikit-learn \
    sysv_ipc \
    pyparsing==2.4.7

RUN git clone https://github.com/vul337/IDFuzz.git

CMD ["/bin/bash"]
