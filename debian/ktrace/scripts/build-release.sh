#!/usr/bin/env bash
set -euo pipefail

# Build a release binary into ./dist

make generate
make build-static

echo "Artifacts in ./dist:"
ls -lah dist
