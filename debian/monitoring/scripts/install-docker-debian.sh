#!/usr/bin/env bash
set -euxo pipefail

# remove old versions
apt-get remove -y docker docker-engine docker.io containerd runc || true

# deps
apt-get update
apt-get install -y ca-certificates curl gnupg lsb-release

# gpg key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | \
  gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# repo for Debian 13 "trixie"
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/debian \
$(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

# install engine + cli + plugins
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# enable + start
systemctl enable --now docker

# test
docker run hello-world || true
echo "Docker installed."
