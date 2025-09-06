#!/usr/bin/env bash
# install-docker-ubuntu-25.04.sh
set -euxo pipefail

# Re-exec with sudo if not root
if [[ "${EUID:-$UID}" -ne 0 ]]; then exec sudo -E "$0" "$@"; fi

# 1) Remove conflicting packages (per Docker docs)
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
  apt-get remove -y "$pkg" || true
done

# 2) Prereqs
apt-get update
apt-get install -y ca-certificates curl gnupg lsb-release

# 3) Keyring (Ubuntu path + .asc)
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# 4) Choose repo codename. Prefer this OS codename; if not available on Docker's repo, fall back to "noble" (24.04).
. /etc/os-release
CODENAME="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
REPO_CODENAME="$CODENAME"
if ! curl -fsSIL "https://download.docker.com/linux/ubuntu/dists/${CODENAME}/Release" >/dev/null; then
  echo "Docker repo for ${CODENAME} not found; falling back to 'noble'."
  REPO_CODENAME="noble"
fi

# 5) Repo
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${REPO_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list

# 6) Install engine + CLI + plugins
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 7) Enable and start
systemctl enable --now docker

# 8) Optionally add the invoking user to the docker group (take effect after re-login)
if [[ -n "${SUDO_USER:-}" ]] && id -u "${SUDO_USER}" >/dev/null 2>&1; then
  usermod -aG docker "${SUDO_USER}" || true
fi

# 9) Smoke test
docker run --rm hello-world || true
echo "Docker installed."
