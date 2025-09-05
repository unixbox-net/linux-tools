#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export DOCKER_BUILDKIT=1
docker build --network host --pull -t socket-snoop:latest .

exec docker run --rm -it \
  --privileged \
  --pid=host \
  --net=host \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /sys:/sys:ro \
  -v /var/log:/var/log \
  socket-snoop:latest \
  /app/.venv/bin/python /app/socket_snoop.py --log-file /var/log/socket_monitor.log
