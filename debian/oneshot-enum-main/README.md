# oneshot-enum

A **one-shot**, Docker-friendly enumerator with safe automations and clean HTML reporting.

- Targets Linux & Windows/AD
- No Kali required
- Professional module layout, single CLI: `oneshot-enum`
- Default rules embedded; optionally override with your own YAML
- Generates JSON + HTML report; optional service-specific follow-ups (SMB/LDAP/AD/etc.)

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
