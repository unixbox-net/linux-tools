#!/usr/bin/env bash
set -euo pipefail

# Prefer installed console_script if present
if command -v oneshot-enum >/dev/null 2>&1; then
  exec oneshot-enum "$@"
fi

# Fallback to source tree
if [ -f /app/src/oneshot_enum/cli.py ]; then
  export PYTHONPATH=/app:$PYTHONPATH
  exec python /app/src/oneshot_enum/cli.py "$@"
fi

echo "ERROR: cannot find oneshot-enum (binary or source). Check your repo layout." >&2
exit 1

