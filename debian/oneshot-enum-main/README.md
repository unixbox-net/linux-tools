# oneshot-enum

oneshot-enum is a one-shot, production-grade enumeration pipeline for
Linux and Windows/Active Directory environments. It performs full-scope
recon with a single command, combining high‑speed port scanning, HTTP(S)
probing, rule‑based automation, eBPF socket telemetry, screenshot
capture, and AI‑ready structured output.

## Key Features

-   **Single‑command enumeration**
    -   Run `oneshot-enum <target>` and get ports, services, web
        discovery, screenshots, and automation outputs.
-   **Rules‑based automations**
    -   A YAML rules engine triggers follow‑up actions based on detected
        ports/services.
    -   Supports nmap, testssl, nuclei, SMB/LDAP tools, Impacket, custom
        scripts, and anything else you add.
-   **AI/LLM‑ready output**
    -   Clean JSON with normalized fields.
    -   Logs, artifacts, screenshots, and results stored in structured
        directories.
    -   Perfect for automated triage, summarization, or risk analysis
        via LLMs.
-   **eBPF-powered runtime telemetry**
    -   The `socketsnoop` module uses BCC/eBPF to monitor live socket
        events.
    -   Outputs structured JSON for anomaly detection or deep workflow
        analysis.
-   **Screenshot pipeline**
    -   Web URL discovery + screenshot capture via the `webshot`
        service.
    -   Reports embed screenshots directly into the HTML report.
-   **Log screening & diagnostics**
    -   `loghog` for ultra-fast log triage, IOC pattern matching, regex
        hunts, and extraction.
    -   Container and system log collectors for automated audits.
-   **Docker-native architecture**
    -   Scanner, screenshot engine, reporter, eBPF tools, MinIO, and
        Postgres run independently.
    -   Works locally or fully automated inside CI/CD pipelines.

## High-Level Workflow

1.  **Scan target**

        oneshot-enum <target> --full --automate --out out.json --report-html report.html

2.  **Discover**

    -   Open ports & services\
    -   Web endpoints & redirects\
    -   TLS details & tech stack fingerprints\
    -   Active Directory ports (SMB/LDAP/Kerberos/WinRM)

3.  **Automate**

    -   Trigger rules that call external tools (nmap, testssl, nuclei,
        smbclient, enum4linux-ng, etc.)
    -   Save all results under `out/actions/`

4.  **Capture**

    -   Generate URLs\
    -   Screenshot all endpoints\
    -   Store as structured evidence

5.  **Report**

    -   Produce `out/report.html`
    -   Produce AI-friendly `out.json`

## Automation Rules

Rules are written in YAML and define:

-   `match` -- ports/services to trigger on\
-   `set` -- environment variables injected into actions\
-   `actions` -- commands to run

Example rule:

``` yaml
- match:
    ports: [443]
  set:
    scheme: "https"
  actions:
    - name: testssl
      require: ["testssl.sh"]
      run: |
        testssl.sh ${SCHEME}://${HOST}:${PORT} > ${OUT}/tls.txt 2>&1
```

## eBPF Socket Telemetry

`socketsnoop` monitors:

-   Connection attempts\
-   State transitions\
-   Source/destination IPs\
-   Ports\
-   Timing

Outputs JSON‑lines suitable for:

-   Grafana/Loki ingestion\
-   Forensic analysis\
-   LLM workflows ("explain anomalous behavior", "summarize flows")

## Loghog: Log Screening Engine

`loghog` provides:

-   Regex/IOC pattern matching\
-   URL/IP extraction\
-   Context-aware log traversal\
-   High-speed filtering

Great for post-scan triage or feeding logs to an AI summarizer.

## Installation (Python)

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e .
    oneshot-enum --help

## Installation (Docker)

    docker build -t oneshot-enum .
    ./max_scan.sh <target>

## Summary

oneshot-enum is designed for serious operators who need **maximum
discovery with minimal commands**.\
It combines classic recon, modern automation, eBPF visibility,
structured reporting, and AI‑ready data into a single cohesive
toolchain.

Use it for: - Automated recon - Pentest preparation - Continuous asset
monitoring - CI/CD exposure scanning - AI-assisted analysis

## Quick start (Docker)

```bash
# Build image
docker build -t oneshot-enum .

# Run against a target, write artifacts to ./out
mkdir -p out
docker run --rm \
  -e AD_DOMAIN -e AD_USER -e AD_PASS -e KRB5CCNAME -e AD_ENUM_SAFE -e ALLOW_ROAST -e ALLOW_BRUTE \
  -v "$PWD/out:/work/out" oneshot-enum \
  oneshot-enum --full example.com \
  --out /work/out/out.json --report-html /work/out/report.html --assume-yes --automate
```

# oneshot-enum (full stack)

Scanner + DB + object storage + eBPF sidecar + log triage + ingestor + OWASP-style report.

## Quickstart (Linux host)

```bash
cp .env.example .env
docker compose build

# infra
docker compose up -d postgres minio createbuckets

# (optional) run eBPF socketsnoop in a separate terminal
docker compose run --rm socketsnoop --active-only

# run a scan
docker compose run --rm scanner \
  --full 10.10.10.10 \
  --out /out/out.json \
  --report-html /out/report.html \
  --actions-out /out/actions \
  --assume-yes --automate

# ingest outputs -> Postgres + MinIO
docker compose run --rm ingestor

# generate OWASP-style HTML report
docker compose run --rm reporter --target 10.10.10.10 --outdir /reports
```

## Screenshots + Observability + Fully inlined Report

```bash
# build everything
docker compose build

# bring up core infra
docker compose up -d postgres minio createbuckets

# run scan (Linux host for host net)
docker compose run --rm scanner --full <TARGET> --out /out/out.json --report-html /out/report.html --actions-out /out/actions --assume-yes --automate

# make URLs and take screenshots
docker compose run --rm --profile screens urlgen
docker compose run --rm --profile screens webshot

# (optional) collect eBPF in parallel (Linux host)
docker compose run --rm --profile observe socketsnoop --active-only

# ship logs for exploration
docker compose up -d --profile obs loki promtail grafana
# Grafana: http://localhost:3000  (user: admin / pass: changeme)
# Loki datasource URL: http://loki:3100

# ingest artifacts -> DB + MinIO
docker compose run --rm --profile ingest ingestor

# generate a SINGLE FILE report (everything baked in)
docker compose run --rm --profile report reporter --target <TARGET> --outdir /reports

# final HTML:
#   ./reports/<TARGET>.html  (self-contained: screenshots + text/json excerpts embedded)
```
