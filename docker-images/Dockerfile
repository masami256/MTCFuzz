FROM ubuntu:24.04

RUN apt update && DEBIAN_FRONTEND=noninteractive apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends \
    qemu-user-static \
    qemu-utils \
    vim \
    wget \
    ca-certificates \
    locales \
    sudo \
    binfmt-support \
    sed \
    git \
    python3 \
    python-is-python3 \
    gcc-riscv64-linux-gnu \
    g++-riscv64-linux-gnu \
    build-essential \
    libncurses-dev \
    bison \
    flex \
    libssl-dev \
    bc \
    unzip \
    patch \
    rsync \
    file \
    openssh-client \
    gdb-multiarch \
    gdb \
    repo \
    python3-pyelftools \
    python3-cryptography \
    python3-yaml \
    netcat-openbsd \
    tmux \
    jq

RUN sed 's/Types: deb/Types: deb deb-src/g' -i /etc/apt/sources.list.d/ubuntu.sources
RUN apt update
RUN apt build-dep -y linux qemu

RUN userdel -r ubuntu
RUN useradd -m build -u 1000
RUN echo "build ALL=(ALL) NOPASSWD: ALL" | tee -a /etc/sudoers
RUN echo  "Defaults env_keep += \" http_proxy https_proxy no_proxy\"" | tee -a /etc/sudoers

RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
        echo 'LANG="en_US.UTF-8"'>/etc/default/locale && \
        dpkg-reconfigure --frontend=noninteractive locales && \
        update-locale LANG=en_US.UTF-8

ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8

USER build
WORKDIR /home/build
CMD ["/bin/bash"]
