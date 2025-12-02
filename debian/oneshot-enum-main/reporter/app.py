import os, base64, json
from pathlib import Path
import psycopg2
from jinja2 import Environment, FileSystemLoader, select_autoescape

DB = os.environ["DATABASE_URL"]
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY")
MINIO_BUCKET = os.environ.get("MINIO_BUCKET","oneshot-artifacts")

OUTDIR = Path("/reports")
LOCAL_OUT = Path("/out")  # mounted for inline embedding

MAX_TEXT_BYTES = int(os.environ.get("REPORT_MAX_TEXT_BYTES", str(300_000)))  # ~300KB per artifact

def fetch(conn, q, args=()):
    with conn.cursor() as cur:
        cur.execute(q, args)
        return cur.fetchall()

def one(conn, q, args=()):
    with conn.cursor() as cur:
        cur.execute(q, args)
        return cur.fetchone()

def read_small(fp: Path):
    try:
        b = fp.read_bytes()
        if len(b) > MAX_TEXT_BYTES:
            return b[:MAX_TEXT_BYTES], True
        return b, False
    except Exception:
        return None, False

def is_image(fp: Path):
    return fp.suffix.lower() in (".png",".jpg",".jpeg",".gif",".webp")

def is_textlike(fp: Path):
    return fp.suffix.lower() in (".txt",".log",".json",".yaml",".yml",".xml",".md",".html",".htm",".ndjson",".jsonl")

def embed_file(fp: Path):
    if not fp.exists(): return None
    if is_image(fp):
        data = base64.b64encode(fp.read_bytes()).decode()
        mime = "image/png" if fp.suffix.lower()==".png" else "image/jpeg"
        return {"kind":"image","dataurl": f"data:{mime};base64,{data}", "name": fp.name}
    if is_textlike(fp):
        b, truncated = read_small(fp)
        if b is None: return None
        text = b.decode(errors="replace")
        pretty = text
        if fp.suffix.lower() in (".json",".ndjson",".jsonl"):
            # try to pretty-print small JSONs (not NDJSON)
            try:
                if "\n" not in text.strip():
                    pretty = json.dumps(json.loads(text), indent=2)
            except Exception:
                pass
        return {"kind":"text","text": pretty, "truncated": truncated, "name": fp.name}
    # default: do not inline binaries
    return None

def eBPF_summary():
    jpath = LOCAL_OUT / "bpf" / "socketsnoop.jsonl"
    counts = {"events":0,"conns":0,"top_dsts":{}}
    if not jpath.exists(): return counts
    seen = set()
    try:
        with jpath.open() as f:
            for line in f:
                counts["events"] += 1
                try:
                    j = json.loads(line)
                    key = (j.get("src_ip"), j.get("src_port"), j.get("dst_ip"), j.get("dst_port"))
                    seen.add(key)
                    dst = f"{j.get('dst_ip')}:{j.get('dst_port')}"
                    counts["top_dsts"][dst] = counts["top_dsts"].get(dst,0)+1
                except Exception:
                    pass
        counts["conns"] = len(seen)
    except Exception:
        pass
    # normalize top 10
    counts["top_dsts"] = sorted(counts["top_dsts"].items(), key=lambda x:x[1], reverse=True)[:10]
    return counts

def collect_screens():
    root = LOCAL_OUT / "screens"
    imgs=[]
    if not root.exists(): return imgs
    for fp in sorted(root.glob("*.png")):
        emb = embed_file(fp)
        if emb and emb["kind"]=="image":
            imgs.append({"name": fp.name, "dataurl": emb["dataurl"]})
    return imgs

def render_html(conn, target_name: str, outdir: Path):
    tgt = one(conn, "SELECT id, name, created_at FROM targets WHERE name=%s", (target_name,))
    if not tgt:
        raise SystemExit(f"Target not found: {target_name}")
    tid = tgt[0]

    services = fetch(conn, """
      SELECT id, proto, port, COALESCE(product,''), COALESCE(version,''), COALESCE(tls,false), COALESCE(metadata,'{}'::jsonb)
      FROM services WHERE target_id=%s ORDER BY port
    """, (tid,))

    artifacts = fetch(conn, """
      SELECT id, tool, path, object_url, created_at, service_id
      FROM run_artifacts
      WHERE target_id=%s
      ORDER BY created_at
    """, (tid,))

    # Inline artifact contents when available on local /out
    inlined=[]
    for (aid, tool, path, object_url, created_at, sid) in artifacts:
        local = None
        try:
            # prefer local path
            p = Path(path)
            if not p.is_absolute():
                p = LOCAL_OUT / p
            local = p if p.exists() else None
        except Exception:
            local = None

        embed = embed_file(local) if local else None
        inlined.append({
          "id": aid, "tool": tool, "created_at": created_at, "service_id": sid,
          "path": path, "object_url": object_url,
          "inline": embed  # {"kind": "image"/"text", ...} or None
        })

    env = Environment(
      loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
      autoescape=select_autoescape()
    )
    tmpl = env.get_template("report.html.j2")
    html = tmpl.render(
      target={"id": tid, "name": tgt[1], "created_at": tgt[2]},
      services=[{
        "id": s[0], "proto": s[1], "port": s[2],
        "product": s[3], "version": s[4], "tls": s[5], "metadata": s[6]
      } for s in services],
      artifacts=inlined,
      ebpf=eBPF_summary(),
      screenshots=collect_screens(),
      max_text_bytes=MAX_TEXT_BYTES
    )
    out = outdir / f"{target_name}.html"
    out.write_text(html, encoding="utf-8")
    print(f"Wrote {out}")

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="target name/ip")
    ap.add_argument("--outdir", default="/reports")
    args = ap.parse_args()
    OUTDIR = Path(args.outdir); OUTDIR.mkdir(parents=True, exist_ok=True)
    conn = psycopg2.connect(DB)
    try:
        render_html(conn, args.target, OUTDIR)
    finally:
        conn.close()
