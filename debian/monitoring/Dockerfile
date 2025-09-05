# Debian 13 (trixie), slim base
FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Speed up apt during build via BuildKit caches (enable with DOCKER_BUILDKIT=1)
RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt/lists \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      # BCC + bindings
      bpfcc-tools libbpfcc-dev python3-bpfcc \
      # Python runtime + venv + pip
      python3 python3-venv python3-pip \
      # Toolchain for eBPF compile
      clang llvm make gcc \
      # Basics
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Only pytest is needed from pip; bcc comes from apt
COPY requirements.txt /app/

# NOTE: --system-site-packages so venv can import 'bcc' from system site-packages
RUN python3 -m venv --system-site-packages /app/.venv && \
    /app/.venv/bin/pip install --upgrade pip && \
    /app/.venv/bin/pip install -r requirements.txt

# Copy app sources last for better layer caching
COPY . /app/

# Default command (can be overridden at docker run)
CMD ["/app/.venv/bin/python", "/app/socket_snoop.py"]
