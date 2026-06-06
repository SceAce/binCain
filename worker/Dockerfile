FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PYTHONUNBUFFERED=1 \
    WORKSPACE=/home/kali/workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    afl++ \
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
    ltrace \
    make \
    ncat \
    patchelf \
    python3 \
    python3-pip \
    qemu-user \
    qemu-user-static \
    radare2 \
    ripgrep \
    ruby \
    socat \
    strace \
    tmux \
    wget \
    xz-utils \
    yq \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && npm install -g @anthropic-ai/claude-code @openai/codex \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir \
    angr \
    capstone \
    pwntools \
    pwninit \
    ROPGadget \
    ropper \
    unicorn \
    z3-solver

RUN gem install seccomp-tools

RUN useradd -m -s /bin/bash kali \
    && mkdir -p "$WORKSPACE"/{target,scripts,fuzz,crashes,findings,notes,proofs} \
    && chown -R kali:kali /home/kali

WORKDIR /opt/binCain
COPY pyproject.toml ./
COPY src ./src
COPY worker/AGENTS.md /home/kali/AGENTS.md
COPY worker/AGENTS.md /home/kali/workspace/AGENTS.md
COPY worker/AGENTS.md /home/kali/CLAUDE.md
COPY worker/AGENTS.md /home/kali/workspace/CLAUDE.md
COPY worker/templates /home/kali/templates
COPY worker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN python3 -m pip install --no-cache-dir . \
    && binCain-init --help >/dev/null \
    && binCain-triage --help >/dev/null \
    && binCain-report --help >/dev/null \
    && binCain-repro --help >/dev/null \
    && binCain-primitive --help >/dev/null \
    && binCain-protocol-template --help >/dev/null \
    && binCain-loop --help >/dev/null \
    && binCain-asset --help >/dev/null \
    && cd "$WORKSPACE" && git init

WORKDIR /home/kali/workspace

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
