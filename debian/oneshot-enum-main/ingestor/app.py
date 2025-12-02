#!/usr/bin/env python3
import os, sys, json, pathlib, hashlib
import psycopg2
from psycopg2.extras import Json

OUT = pathlib.Path(os.environ.get("OUT_DIR", "/out"))

def load_jsonl(p: pathlib.Path):
    if not p.exists():
        return []
    rows = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows

def db():
    return psycopg2.connect(
        host=os.environ.get("PGHOST","postgres"),
        user=os.environ.get("PGUSER","postgres"),
        password=os.environ.get("PGPASSWORD","postgres"),
        dbname=os.environ.get("PGDATABASE","oneshot"),
    )

def table_cols(cur, tbl):
    cur.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name=%s
    """, (tbl,))
    return {r[0] for r in cur.fetchall()}

def insert_dynamic(cur, table, rowdict):
    cols = table_cols(cur, table)
    keys = [k for k in rowdict.keys() if k in cols]
    if not keys:
        return 0
    placeholders = ", ".join(["%s"]*len(keys))
    collist = ", ".join(keys)
    cur.execute(f"INSERT INTO {table} ({collist}) VALUES ({placeholders})", [rowdict[k] for k in keys])
    return 1

def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    OUT.mkdir(parents=True, exist_ok=True)

    # metadata
    target = None
    meta = {}
    try:
        meta = json.loads((OUT/"out.json").read_text())
        target = meta.get("target")
    except Exception:
        pass

    conn = db()
    cur = conn.cursor()

    # scan row
    cur.execute("INSERT INTO scans (target, metadata) VALUES (%s, %s) RETURNING id", (target, Json(meta)))
    scan_id = cur.fetchone()[0]
    conn.commit()
    print(f"[ingestor] scan_id={scan_id}", flush=True)

    # httpx.jsonl -> httpx_pages
    httpx_rows = load_jsonl(OUT/"httpx.jsonl")
    httpx_inserted = 0
    for obj in httpx_rows:
        row = {
            "scan_id": scan_id,
            "url": obj.get("url") or obj.get("final_url") or obj.get("host"),
            "status": obj.get("status_code") or obj.get("status"),
            "title": obj.get("title"),
            "server": obj.get("webserver") or obj.get("server"),
            "raw": Json(obj),
        }
        try:
            httpx_inserted += insert_dynamic(cur, "httpx_pages", row)
        except Exception as e:
            # fallback: if only (scan_id, raw) exists
            try:
                cur.execute("INSERT INTO httpx_pages (scan_id, raw) VALUES (%s,%s)", (scan_id, Json(obj)))
                httpx_inserted += 1
            except Exception:
                conn.rollback()
            else:
                conn.commit()
                continue
    conn.commit()
    print(f"[ingestor] httpx_pages inserted: {httpx_inserted}", flush=True)

    # nuclei.jsonl -> nuclei_findings
    nuclei_rows = load_jsonl(OUT/"nuclei.jsonl")
    nuclei_inserted = 0
    for obj in nuclei_rows:
        info = obj.get("info") or {}
        row = {
            "scan_id": scan_id,
            "template_id": obj.get("template-id") or obj.get("templateID"),
            "severity": (info.get("severity") or obj.get("severity")),
            "matched_at": obj.get("matched-at") or obj.get("matched"),
            "type": info.get("type") or obj.get("type"),
            "name": info.get("name"),
            "raw": Json(obj),
        }
        try:
            nuclei_inserted += insert_dynamic(cur, "nuclei_findings", row)
        except Exception:
            try:
                cur.execute("INSERT INTO nuclei_findings (scan_id, raw) VALUES (%s,%s)", (scan_id, Json(obj)))
                nuclei_inserted += 1
            except Exception:
                conn.rollback()
            else:
                conn.commit()
                continue
    conn.commit()
    print(f"[ingestor] nuclei_findings inserted: {nuclei_inserted}", flush=True)

    # artifacts: stash important files + hashes
    art_inserted = 0
    keep = {
        "out.json", "urls.txt", "nuclei.jsonl", "nuclei.txt",
        "httpx.jsonl", "testssl-443.txt", "report.html"
    }
    # screenshots + log bundles + bpf stuff
    extra_dirs = ["shots", "loghog", "bpf"]
    paths = []
    for name in keep:
        p = OUT/name
        if p.exists():
            paths.append(p)
    for d in extra_dirs:
        base = OUT/d
        if base.exists():
            for p in base.rglob("*"):
                if p.is_file():
                    paths.append(p)

    for p in paths:
        rel = str(p.relative_to(OUT))
        try:
            h = sha256_file(p)
            size = p.stat().st_size
            cur.execute(
                "INSERT INTO artifacts (scan_id, path, size_bytes, sha256) VALUES (%s,%s,%s,%s)",
                (scan_id, rel, size, h),
            )
            art_inserted += 1
        except Exception:
            conn.rollback()
        else:
            conn.commit()
    print(f"[ingestor] artifacts inserted: {art_inserted}", flush=True)

    print("[ingestor] done.", flush=True)

if __name__ == "__main__":
    main()

