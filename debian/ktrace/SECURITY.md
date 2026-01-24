# Security Policy

## Scope

`ktrace` is a privileged, kernel-adjacent diagnostic tool. Security issues may include:

- unintended data exposure beyond documented metadata
- privilege escalation vectors in the loader or runtime behavior
- unsafe default configurations that could cause excessive load or instability

## Reporting a Vulnerability

Please report security issues privately:

- Email: security@your-org.example (replace with your org address)
- Include: version/commit, kernel version, reproduction steps, and impact assessment

Do **not** open a public issue for active vulnerabilities.

## Hardening guidance

- Run `ktrace` as an **on-demand snapshot** (30–120s), not a permanent daemon.
- Prefer `--ports` / `--dns-only` / `--sample` to reduce surface and volume.
- Store bundles in restricted directories; treat JSONL as sensitive operational telemetry.
- Do not enable extra probes you do not need.
