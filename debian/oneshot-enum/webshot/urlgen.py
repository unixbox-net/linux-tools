import sys, json, pathlib

if len(sys.argv) != 3:
    print("Usage: urlgen.py /out/out.json /out/urls.txt", file=sys.stderr); sys.exit(2)

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
if not src.exists():
    dst.parent.mkdir(parents=True, exist_ok=True)
    open(dst, "w").close()
    sys.exit(0)

d = json.load(open(src))
host = d.get("host") or d.get("target") or "localhost"
ports = (d.get("ports") or {}).get("open", []) or d.get("ports_open", [])
urls = []
for p in ports:
    try:
        p = int(p)
    except Exception:
        continue
    if p in (80,8080,8000,3000): urls.append(f"http://{host}:{p}/")
    if p in (443,8443):          urls.append(f"https://{host}:{p}/")

dst.parent.mkdir(parents=True, exist_ok=True)
open(dst, "w").write("\n".join(sorted(set(urls))))
print(f"[urlgen] wrote {dst} ({len(urls)} urls)")

