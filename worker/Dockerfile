FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PYTHONUNBUFFERED=1 \
    WORKSPACE=/home/kali/workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    ca-certificates \
    curl \
    file \
    g++ \
    gcc \
    gdb \
    gdb-multiarch \
    git \
    jq \
    make \
    ncat \
    patchelf \
    python3 \
    python3-pip \
    qemu-user \
    qemu-user-static \
    ripgrep \
    socat \
    wget \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir \
    capstone \
    pwntools \
    ROPGadget \
    ropper \
    unicorn \
    z3-solver

RUN useradd -m -s /bin/bash kali \
    && mkdir -p "$WORKSPACE"/{target,scripts,fuzz,crashes,findings,notes,proofs} \
    && chown -R kali:kali /home/kali

WORKDIR /opt/binCain
COPY pyproject.toml ./
COPY src ./src
COPY worker/AGENTS.md /home/kali/AGENTS.md
COPY worker/templates /home/kali/templates

RUN python3 -m pip install --no-cache-dir . \
    && binCain-init --help >/dev/null \
    && binCain-triage --help >/dev/null \
    && binCain-repro --help >/dev/null \
    && binCain-primitive --help >/dev/null

USER kali
WORKDIR /home/kali/workspace

CMD ["/bin/bash"]
