FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 DEBIAN_FRONTEND=noninteractive

# OS tools (trim as you like)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq unzip bash \
    nmap whatweb wafw00f ffuf smbclient smbmap nbtscan \
    ldap-utils krb5-user dnsutils netcat-openbsd openssl whois \
    rpcbind nfs-common snmp dirb \
  && rm -rf /var/lib/apt/lists/*

# testssl.sh
RUN git clone --depth=1 https://github.com/drwetter/testssl.sh /opt/testssl.sh \
 && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# nuclei: follow redirect to resolve latest tag safely
RUN set -eux; \
  arch="$(uname -m)"; case "$arch" in x86_64) arch="amd64";; aarch64) arch="arm64";; *) echo "Unsupported $arch"; exit 1;; esac; \
  ver="$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/projectdiscovery/nuclei/releases/latest | sed -E 's#.*/tag/v?([^/]+).*#\1#')"; \
  curl -fSLo /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${ver}/nuclei_${ver}_linux_${arch}.zip"; \
  cd /tmp && unzip -o nuclei.zip && install -m0755 nuclei /usr/local/bin/nuclei && rm -f nuclei.zip

WORKDIR /app
COPY . /app

# Python deps (EDIT to match your package)
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir -e . \
 && pip install --no-cache-dir \
      ssh-audit ipwhois mmh3 waybackpy tldextract python-whois lxml beautifulsoup4 cryptography \
      impacket certipy-ad adidnsdump ldapdomaindump \
 && mkdir -p /usr/share/wordlists/dirb \
 && if [ -f /usr/share/dirb/wordlists/common.txt ]; then ln -sf /usr/share/dirb/wordlists/common.txt /usr/share/wordlists/dirb/common.txt; fi

VOLUME ["/out"]
ENTRYPOINT ["oneshot-enum"]

