SHELL := /bin/bash
GO ?= go
OUT ?= dist

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make generate      Generate bpf/vmlinux.h and Go BPF bindings (bpf2go)"
	@echo "  make build         Build ktrace (native)"
	@echo "  make build-static  Build static-ish linux/amd64 (CGO disabled userland)"
	@echo "  make clean"

.PHONY: generate
generate:
	@./scripts/gen-vmlinuxh.sh ./bpf/vmlinux.h
	@# Ensure tool deps are present (bpf2go) and module deps are resolved.
	@command -v bpf2go >/dev/null 2>&1 || (echo "[generate] installing bpf2go" && $(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest)
	@$(GO) mod tidy -tags tools
	@$(GO) generate ./...

.PHONY: build
build:
	@mkdir -p $(OUT)
	@$(GO) build -trimpath -ldflags="-s -w" -o $(OUT)/ktrace ./cmd/ktrace

.PHONY: build-static
build-static:
	@mkdir -p $(OUT)
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o $(OUT)/ktrace-linux-amd64 ./cmd/ktrace

.PHONY: clean
clean:
	@rm -rf $(OUT)
	@rm -f ./bpf/vmlinux.h
	@rm -f ./internal/bpf/ktrace_bpf*.go
	@rm -f ./internal/bpf/ktrace*.o
