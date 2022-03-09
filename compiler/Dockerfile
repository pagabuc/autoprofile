FROM debian:buster

RUN apt-get update && apt-get install -y wget build-essential ninja-build cmake python3 libjsoncpp-dev \
                                         flex bison libssl-dev bc libelf-dev bear rsync

COPY clang/ /compiler/clang
WORKDIR /compiler/clang/
RUN bash install-clang-9.sh

WORKDIR /compiler/clang/plugin
RUN make

RUN apt-get update && apt-get install -y libncurses-dev gawk libssl-dev dkms libudev-dev libpci-dev libiberty-dev autoconf cpio

COPY make_kernel_dist.sh /compiler/
COPY make_kernel_allyes.sh /compiler/
COPY clang-profile /compiler/
COPY run_clang.py /compiler/
