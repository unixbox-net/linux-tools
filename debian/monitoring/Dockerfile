# Debian 13 (trixie), slim base
FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Speed up apt via BuildKit cache mounts (DOCKER_BUILDKIT=1 required)
RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt/lists \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      bpfcc-tools libbpfcc-dev python3-bpfcc \
      python3 python3-venv python3-pip \
      clang llvm make gcc ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/

# NOTE: --system-site-packages so venv can import 'bcc' (installed system-wide)
RUN python3 -m venv --system-site-packages /app/.venv && \
    ln -sf python3 /app/.venv/bin/python && \
    /app/.venv/bin/pip install --upgrade pip && \
    /app/.venv/bin/pip install -r requirements.txt

COPY . /app/

# Use python3 in CMD (safe), but thanks to symlink python also exists
CMD ["/app/.venv/bin/python3", "/app/socket_snoop.py"]

