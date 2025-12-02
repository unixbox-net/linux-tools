FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates tar gzip findutils coreutils jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

