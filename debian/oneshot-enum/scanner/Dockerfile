FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq unzip bash nmap whatweb wafw00f ffuf bsdextrautils \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh
RUN git clone --depth=1 https://github.com/drwetter/testssl.sh /opt/testssl.sh \
    && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# httpx + nuclei (arch-aware; matches current GitHub asset names)
RUN set -eux; \
    arch="$(uname -m)"; case "$arch" in x86_64) GOARCH="amd64" ;; aarch64) GOARCH="arm64" ;; *) echo "Unsupported: $arch"; exit 1 ;; esac; \
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v1.7.1/httpx_1.7.1_linux_${GOARCH}.zip" -o /tmp/httpx.zip; \
    unzip -p /tmp/httpx.zip httpx > /usr/local/bin/httpx; chmod +x /usr/local/bin/httpx; rm /tmp/httpx.zip; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.9/nuclei_3.3.9_linux_${GOARCH}.zip" -o /tmp/nuclei.zip; \
    unzip -p /tmp/nuclei.zip nuclei > /usr/local/bin/nuclei; chmod +x /usr/local/bin/nuclei; rm /tmp/nuclei.zip

# Python deps your script needs
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir ssh-audit ipwhois mmh3 waybackpy tldextract python-whois lxml beautifulsoup4

WORKDIR /app
COPY oneshot.sh /app/oneshot.sh
RUN chmod +x /app/oneshot.sh
ENTRYPOINT ["/app/oneshot.sh"]

# Helpful Python libs
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir \
      ssh-audit ipwhois mmh3 waybackpy tldextract python-whois lxml beautifulsoup4 cryptography \
      requests urllib3

VOLUME ["/out"]
ENTRYPOINT ["/app/oneshot.sh"]

