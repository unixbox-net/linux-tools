#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET:-${1:-}}"
[[ -z "${TARGET}" ]] && { echo "usage: TARGET=<ip-or-host> $0"; exit 1; }

OUT_DIR="/out"
mkdir -p "${OUT_DIR}"/{shots,}

ts() { date +'%Y-%m-%d %H:%M:%S'; }

echo "[$(ts)] Target: ${TARGET}"
echo "[$(ts)] Out JSON: ${OUT_DIR}/out.json"
echo "[$(ts)] Report: ${OUT_DIR}/report.html"

# 1) nmap quick
echo "[$(ts)] Running nmap (quick)…"
mapfile -t PORTS < <(nmap -Pn -n --top-ports 200 --min-rate 200 -T4 -oG - "${TARGET}" \
  | awk '/Ports:/{print $0}' \
  | sed -E 's#.*Ports: ##' | tr ',' '\n' | awk -F/ '{print $1" "$2" "$3" "$5}' \
  | awk '$2=="open"{print $1}' | sort -n | uniq)
OPEN_PORTS="${PORTS[*]:-}"

echo "[$(ts)] Open ports: ${OPEN_PORTS:-none}"

# 2) httpx (NO jq; write jsonl directly)
echo "[$(ts)] Running httpx…"
HTTPX_OUT="${OUT_DIR}/httpx.jsonl"
> "${HTTPX_OUT}" || true

# try common schemes if 80/443 exist, otherwise just try both
SCHEMES=()
if echo " ${OPEN_PORTS} " | grep -q ' 80 '; then SCHEMES+=("http"); fi
if echo " ${OPEN_PORTS} " | grep -q ' 443 '; then SCHEMES+=("https"); fi
[[ ${#SCHEMES[@]} -eq 0 ]] && SCHEMES=("http" "https")

for sch in "${SCHEMES[@]}"; do
  httpx -silent -json -follow-redirects -title -tech-detect -status-code -content-type \
        -tls-probe -no-color -host "${sch}://${TARGET}" \
        >> "${HTTPX_OUT}" || true
done

# 3) nuclei (be tolerant of versions)
echo "[$(ts)] Running nuclei (default templates)…"
NUC_OUT_JSONL="${OUT_DIR}/nuclei.jsonl"
NUC_OUT_JSON="${OUT_DIR}/nuclei.json"
NUC_OUT_TXT="${OUT_DIR}/nuclei.txt"
> "${NUC_OUT_JSONL}" || true

if nuclei -h 2>&1 | grep -q -- '-jsonl'; then
  nuclei -u "http://${TARGET}" -jsonl -o "${NUC_OUT_JSONL}" || true
  nuclei -u "https://${TARGET}" -jsonl -o "${NUC_OUT_JSONL}" || true
elif nuclei -h 2>&1 | grep -q -- '-json'; then
  nuclei -u "http://${TARGET}" -json -o "${NUC_OUT_JSON}" || true
  nuclei -u "https://${TARGET}" -json -o "${NUC_OUT_JSON}" || true
else
  nuclei -u "http://${TARGET}" -o "${NUC_OUT_TXT}" || true
  nuclei -u "https://${TARGET}" -o "${NUC_OUT_TXT}" || true
fi

# 4) testssl if 443 open
if echo " ${OPEN_PORTS} " | grep -q ' 443 '; then
  echo "[$(ts)] Running testssl.sh on 443…"
  /opt/testssl.sh/testssl.sh --color 0 --warnings off --openssl-timeout 5 --fast "https://${TARGET}:443" \
    > "${OUT_DIR}/testssl-443.txt" 2>&1 || true
fi

# 5) Compose out.json (summary)
echo "[$(ts)] Composing out.json…"
{
  echo '{'
  echo "  \"target\": \"${TARGET}\","
  echo "  \"open_ports\": [$(printf '%s\n' "${OPEN_PORTS}" | tr ' ' '\n' | sed '/^$/d' | sed 's/^/"/;s/$/"/' | paste -sd, - )],"
  echo "  \"httpx_file\": \"${HTTPX_OUT##*/}\","
  if [[ -s "${NUC_OUT_JSONL}" ]]; then
    echo "  \"nuclei_file\": \"${NUC_OUT_JSONL##*/}\""
  elif [[ -s "${NUC_OUT_JSON}" ]]; then
    echo "  \"nuclei_file\": \"${NUC_OUT_JSON##*/}\""
  elif [[ -s "${NUC_OUT_TXT}" ]]; then
    echo "  \"nuclei_file\": \"${NUC_OUT_TXT##*/}\""
  else
    echo "  \"nuclei_file\": null"
  fi
  echo '}'
} > "${OUT_DIR}/out.json"

# 6) lightweight HTML stub (the reporter will generate the real one later)
cat > "${OUT_DIR}/report.html" <<HTML
<!doctype html><meta charset="utf-8"><title>oneshot stub</title>
<h1>oneshot scan for ${TARGET}</h1>
<p>Open ports: ${OPEN_PORTS:-none}</p>
<p>httpx: ${HTTPX_OUT##*/}</p>
HTML

echo "[$(ts)] Done."

