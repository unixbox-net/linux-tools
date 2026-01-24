# Contributing

Thanks for considering contributions.

## Development workflow

1. Install build deps: Go, clang/llvm, bpftool
2. Generate vmlinux header and BPF skeleton:

   ```bash
   make generate
   ```

3. Build:

   ```bash
   make build
   ```

## Code style / practices

- Keep BPF programs small and verifier-friendly.
- Prefer bounded loops and fixed-size filters.
- Keep output schema stable and additive (AI analyzers rely on it).
- Avoid payload capture; metadata-only by design.

## Testing

- Unit test user-space parsers (conntrack parsing, CRI label parsing).
- Integration test on a real node kernel with BTF.
