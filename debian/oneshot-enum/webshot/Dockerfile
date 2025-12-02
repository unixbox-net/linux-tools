# webshot/Dockerfile
FROM golang:1.24-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN GOTOOLCHAIN=auto go install github.com/sensepost/gowitness@latest

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates bash chromium fonts-liberation fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /go/bin/gowitness /usr/local/bin/gowitness
WORKDIR /work
ENTRYPOINT ["bash","-lc"]

