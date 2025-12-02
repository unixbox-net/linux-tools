# socketsnoop/Dockerfile
FROM quay.io/iovisor/bcc:latest

# tools used by the fallback path (ps & ss) and shell
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip ca-certificates \
    procps iproute2 bash \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY socketsnoop.py /app/socketsnoop.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Important: we will run the bash wrapper, not python directly
ENTRYPOINT ["/entrypoint.sh"]

