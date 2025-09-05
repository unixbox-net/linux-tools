# Debian 13 (trixie), slim base
FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Speed up apt during build: use BuildKit cache mounts
# (DOCKER_BUILDKIT=1 is required at build time)
RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt/lists \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      bpfcc-tools libbpfcc-dev python3-bpfcc \
      python3 python3-venv python3-pip \
      clang llvm make gcc ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Only pytest is needed from pip; bcc comes from apt
COPY requirements.txt /app/
RUN python3 -m venv /app/.venv && \
    /app/.venv/bin/pip install --upgrade pip && \
    /app/.venv/bin/pip install -r requirements.txt

# Copy the app
COPY . /app/

# Default command (can be overridden)
CMD ["/app/.venv/bin/python", "/app/socket_snoop.py"]
