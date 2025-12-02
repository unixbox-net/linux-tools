import os, json, base64, pathlib
from jinja2 import Environment, FileSystemLoader, select_autoescape

OUT = pathlib.Path("/out")
REPORTS = pathlib.Path("/reports")
REPORTS.mkdir(parents=True, exist_ok=True)

out_json = OUT / "out.json"
actions_dir = OUT / "actions"
screens_dir = OUT / "screens"
bpf_jsonl = OUT / "bpf" / "socketsnoop.jsonl"

data = {}
if out_json.exists():
    data = json.load(open(out_json))
host = data.get("host") or data.get("target") or "unknown"
ports = (data.get("ports") or {}).get("open", []) or data.get("ports_open", [])

# Screenshots → embed base64
screens = []
if screens_dir.exists():
    for p in sorted(screens_dir.glob("*.png")):
        b64 = base64.b64encode(p.read_bytes()).decode()
        screens.append({"name": p.name, "data_uri": f"data:image/png;base64,{b64}"})

# Action artifacts (just list)
artifacts = []
if actions_dir.exists():
    for d in sorted(actions_dir.rglob("*")):
        if d.is_file():
            rel = d.relative_to(OUT)
            size = d.stat().st_size
            if size <= 200_000 and d.suffix in (".txt",".log",".json"):
                try:
                    content = d.read_text(errors="ignore")
                except Exception:
                    content = None
            else:
                content = None
            artifacts.append({"path": str(rel), "size": size, "content": content})

# eBPF head (first 200 lines)
bpf_events = []
if bpf_jsonl.exists():
    with open(bpf_jsonl, "r") as f:
        for i, line in enumerate(f):
            if i >= 200: break
            try:
                bpf_events.append(json.loads(line))
            except Exception:
                pass

env = Environment(
    loader=FileSystemLoader("/app/templates"),
    autoescape=select_autoescape()
)

tmpl = env.get_template("report.html.j2")
html = tmpl.render(
    host=host,
    ports=ports,
    data=data,
    screens=screens,
    artifacts=artifacts,
    bpf_events=bpf_events
)

out_file = REPORTS / f"{host}-oneshot-report.html"
out_file.write_text(html)
print(f"[report] wrote {out_file}")

