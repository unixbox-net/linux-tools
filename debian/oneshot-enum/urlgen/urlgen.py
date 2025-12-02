#!/usr/bin/env python3
import json, pathlib

OUT = pathlib.Path("/out")
HTTPX = OUT / "httpx.jsonl"
OUTJSON = OUT / "out.json"
URLS = OUT / "urls.txt"

def read_httpx():
    urls=set()
    if HTTPX.exists():
        with HTTPX.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line=line.strip()
                if not line: 
                    continue
                try:
                    obj=json.loads(line)
                except Exception:
                    continue
                cand = obj.get("url") or obj.get("final_url") or obj.get("input") or obj.get("host")
                if not cand:
                    continue
                if cand.startswith("http://") or cand.startswith("https://"):
                    urls.add(cand.rstrip("/"))
                else:
                    urls.add("http://" + cand)
                    urls.add("https://" + cand)
    return urls

def seed_from_outjson():
    s=set()
    try:
        j=json.loads(OUTJSON.read_text())
        tgt=j.get("target")
        if tgt:
            s.add(f"http://{tgt}")
            s.add(f"https://{tgt}")
    except Exception:
        pass
    return s

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    urls = read_httpx() | seed_from_outjson()
    with URLS.open("w", encoding="utf-8") as f:
        for u in sorted(urls):
            f.write(u+"\n")
    print(f"[urlgen] wrote {URLS} ({len(urls)} urls)")

if __name__ == "__main__":
    main()

