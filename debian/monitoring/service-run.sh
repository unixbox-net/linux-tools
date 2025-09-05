#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Bootstrap venv if you ever choose to run service via venv
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv --system-site-packages .venv
  .venv/bin/pip install --upgrade pip
  .venv/bin/pip install -r requirements.txt
fi

exec .venv/bin/python socket_snoop.py --log-file /var/log/socket_monitor.log
