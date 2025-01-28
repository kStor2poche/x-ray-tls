ARG BASE_IMAGE=ubuntu:24.04

FROM $BASE_IMAGE

# ARG must be after FROM
ARG BCC_VERSION=v0.31.0
ARG WIRESHARK_COMMIT=3b3b599037161e090a6d5747f685b211c54b4430

# Multi host OS support
RUN . /etc/os-release; \
    if [ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "24.04" ]; then \
        apt-get update && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential cmake linux-headers-$(uname -r) \
        bison cmake flex git libedit-dev \
        libllvm18 llvm-18-dev libclang-18-dev libpolly-18-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
        python3-pip libspeexdsp-dev zip tshark \
        curl libglib2.0-dev libgcrypt-dev libc-ares-dev gnutls-dev libpcap-dev && \
        rm -rf /var/lib/apt/lists/*; \
    elif [ "$ID" = "debian" ] && [ "$VERSION_ID" = "11" ]; then \ 
        echo "TODO: debian 11 support" && exit 1; \
    elif [ "$ID" = "arch" ]; then \ 
        echo "TODO: archlinux support" && exit 1; \
    else \
        echo "Unsupported base OS '$BASE_IMAGE'" && \
        exit 1; \
    fi

# Use our tls-bruteforce binary
RUN \
    cd /tmp && \
    git clone --depth 1 https://github.com/kStor2poche/tls-bruteforce.git && \
    cd tls-bruteforce && \
    make build && \
    cp tls-bf /usr/local/bin/ && \
    cd /tmp && \
    rm -rf /tmp/tls-bruteforce

# Install BCC
RUN \
    cd /tmp && \
    git clone --depth 1 --branch $BCC_VERSION https://github.com/iovisor/bcc.git && \
    mkdir bcc/build && \
    cd bcc/build && \
    cmake .. && \
    make -j$(nproc) && \
    make install && \
    cmake -DPYTHON_CMD=python3 .. && \
    cd src/python/ && \
    make && \
    make install && \
    cd /tmp && \
    rm -rf /tmp/bcc
#RUN \
#    cd /tmp && \
#    git clone https://github.com/iovisor/bcc.git \
#    mkdir bcc/build; cd bcc/build \
#    cmake .. \
#    make \
#    sudo make install \
#    cmake -DPYTHON_CMD=python3 .. # build python3 binding \
#    pushd src/python/ \
#    make \
#    sudo make install \
#    popd

# Install Python dependencies
COPY requirements.txt /opt
RUN pip3 install -r /opt/requirements.txt --break-system-packages

# Add /opt/wireshark-custom/bin/ to PATH
ENV PATH=/opt/wireshark-custom/bin:$PATH

# Copy and compile (Cython) code
ENV PYTHONPATH=/app
WORKDIR /app

COPY setup.py /app
COPY src /app/src

RUN python3 setup.py build_ext --inplace -j$(nproc)

ENTRYPOINT [ "python3", "-u", "src/main.py" ]

