FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    bpfcc-tools libbpfcc-dev python3-bpfcc \
    python3 python3-pip python3-venv \
    clang llvm make gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/
RUN python3 -m venv /app/.venv && /app/.venv/bin/pip install --upgrade pip && /app/.venv/bin/pip install -r requirements.txt
COPY monitoring/ /app/monitoring/

# Example run (host):
# docker run --rm -it --privileged \
#   -v /lib/modules:/lib/modules:ro \
#   -v /usr/src:/usr/src:ro \
#   -v /var/log:/var/log \
#   socket-snoop:latest \
#   /app/.venv/bin/python /app/monitoring/socket-snoop.py
