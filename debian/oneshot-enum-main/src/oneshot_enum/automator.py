import os, re, shlex, subprocess, json, hashlib, time, pathlib, shutil, queue, threading
from typing import Dict, List, Any

def _slug(s:str)->str:
    import re
    return re.sub(r"[^a-zA-Z0-9._-]+","-", s).strip("-")

def _safe_env(extra:dict)->dict:
    env = os.environ.copy()
    for k,v in extra.items():
        env[str(k)] = str(v)
    return env

def _already_done(outdir: pathlib.Path, key: str) -> bool:
    m = outdir / (hashlib.sha256(key.encode()).hexdigest() + ".done")
    return m.exists()

def _mark_done(outdir: pathlib.Path, key: str):
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / (hashlib.sha256(key.encode()).hexdigest() + ".done")).write_text(str(time.time()))

def _write_env_json(outdir: pathlib.Path, env: dict):
    (outdir / "env.json").write_text(json.dumps(env, indent=2))

def _run_bash(script: str, cwd: pathlib.Path, env: dict, timeout: int) -> dict:
    cwd.mkdir(parents=True, exist_ok=True)
    _write_env_json(cwd, env)
    cmd = ["bash","-c", f"set -euo pipefail\n{script}\n"]
    try:
        p = subprocess.run(cmd, cwd=str(cwd), env=env, text=True, capture_output=True, timeout=timeout)
        (cwd/"stdout.log").write_text(p.stdout or "")
        (cwd/"stderr.log").write_text(p.stderr or "")
        return {"rc": p.returncode, "stdout": (p.stdout or "")[-6000:], "stderr": (p.stderr or "")[-6000:]}
    except subprocess.TimeoutExpired as e:
        (cwd/"stdout.log").write_text((e.stdout or ""))
        (cwd/"stderr.log").write_text((e.stderr or "") + "\n[TIMEOUT]")
        return {"rc": 124, "stdout": (e.stdout or "")[-6000:], "stderr": "[TIMEOUT]"}

def load_rules(path: str) -> dict:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def load_default_rules() -> dict:
    from importlib.resources import files
    data = files(__package__).joinpath("rules_default.yaml").read_text(encoding="utf-8")
    import yaml
    return yaml.safe_load(data) or {}

def plan_for(findings: dict, rules: dict) -> list:
    host = findings.get("host")
    open_ports = set(findings.get("open") or [])
    banners = findings.get("banners") or {}
    title_map = findings.get("http_titles") or {}
    jobs = []
    for rule in (rules.get("rules") or []):
        match = rule.get("match", {})
        ports = match.get("ports")
        if ports and not (open_ports & set(ports)):
            continue
        banner_rx = match.get("banner_regex")
        if banner_rx:
            ok=False
            rx=re.compile(banner_rx, re.I)
            for p,b in (banners or {}).items():
                if rx.search(b or ""):
                    ok=True; break
            if not ok: continue
        title_rx = match.get("http_title_regex")
        if title_rx:
            ok=False
            rx=re.compile(title_rx, re.I)
            for p,info in (title_map or {}).items():
                t = (info or {}).get("title") or ""
                if rx.search(t):
                    ok=True; break
            if not ok: continue

        for act in (rule.get("actions") or []):
            ports_for_action = act.get("ports") or (list(open_ports) if not ports else list(set(ports) & open_ports))
            for p in ports_for_action:
                jobs.append({
                    "name": act.get("name"),
                    "script": act.get("run"),
                    "port": int(p),
                    "timeout": int(act.get("timeout", rules.get("defaults",{}).get("timeout", 900))),
                    "set": rule.get("set", {}),
                    "require": act.get("require", []),
                    "when": act.get("when"),
                    "out_dir_tag": act.get("out_dir_tag", ""),
                })
    jobs.sort(key=lambda j: (j["port"], j["name"] or ""))
    uniq, seen = [], set()
    for j in jobs:
        k=(j["name"], j["port"], j["script"])
        if k not in seen:
            uniq.append(j); seen.add(k)
    return uniq

def should_run(expr: str, env: dict) -> bool:
    if not expr: return True
    s = expr.replace(" contains ", " in ")
    for k,v in env.items():
        s = re.sub(rf"\b{k}\b", repr(str(v)), s)
    try:
        return bool(eval(s, {"__builtins__":{}}))
    except Exception:
        return False

def execute(host: str, jobs: list, root_out: str, base_env: dict, max_parallel: int = 4) -> list:
    out = []
    root = pathlib.Path(root_out)
    root.mkdir(parents=True, exist_ok=True)

    q = queue.Queue()
    for j in jobs: q.put(j)
    lock = threading.Lock()

    def worker():
        while True:
            try: j = q.get_nowait()
            except queue.Empty: return
            port = j["port"]
            name = j.get("name") or "action"
            tag = j.get("out_dir_tag","")
            sub = root / f"{port}-{_slug(tag or name)}"
            env = dict(base_env)
            env.update({
                "HOST": host,
                "PORT": str(port),
                "SERVICE": j["set"].get("service",""),
                "SCHEME": j["set"].get("scheme",""),
                "OUT": str(sub),
            })
            for rbin in (j.get("require") or []):
                if shutil.which(rbin) is None:
                    with lock:
                        out.append({"port":port,"name":name,"skipped":"missing-binary", "binary": rbin})
                    q.task_done(); 
                    break
            else:
                if not should_run(j.get("when"), env):
                    with lock:
                        out.append({"port":port,"name":name,"skipped":"when-false"})
                    q.task_done(); continue
                key = f"{host}:{port}:{name}:{hashlib.sha256(j['script'].encode()).hexdigest()}"
                if _already_done(sub, key):
                    with lock:
                        out.append({"port":port,"name":name,"skipped":"cached"})
                    q.task_done(); continue
                res = _run_bash(j["script"], sub, _safe_env(env), j["timeout"])
                _mark_done(sub, key)
                with lock:
                    out.append({"port":port,"name":name,"rc":res["rc"],"stdout_tail":res["stdout"],"stderr_tail":res["stderr"]})
                q.task_done()

    threads = []
    for _ in range(max_parallel):
        t=threading.Thread(target=worker, daemon=True)
        t.start(); threads.append(t)
    for t in threads: t.join()

    (root / "summary.json").write_text(json.dumps(sorted(out, key=lambda x: (x.get("port",0), x.get("name",""))), indent=2))
    return out
