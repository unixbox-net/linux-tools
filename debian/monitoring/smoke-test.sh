#!/usr/bin/env bash
set -euxo pipefail
cd "$(dirname "$0")"

# host deps
sudo ./install-deps-debian.sh

# venv + test
python3 -m venv --system-site-packages .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest -q

# short run
sudo timeout 10s python3 socket_snoop.py --log-file ./socket_monitor.log || true
tail -n 3 ./socket_monitor.log || true

echo "Smoke test completed."
