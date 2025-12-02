import os, json, time
from datetime import datetime, timezone

def _fmt_dt(ts: float) -> str: return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

def _html_escape(s: str) -> str: return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
def _html_section(title: str, body_html: str, anchor: str) -> str: return f'<section id="{anchor}"><h2>{_html_escape(title)}</h2>\n{body_html}\n</section>'

def _derive_highlights(d: dict) -> list:
    notes=[]
    if not (d.get("http_probe") or {}).get("hsts"): notes.append("HSTS not detected on primary host.")
    cert=((d.get("tls") or {}).get("cert") or {}); naf=cert.get("notAfter")
    if naf: notes.append(f"TLS cert notAfter: {naf}")
    sh = ((d.get("web_fingerprint") or {}).get("sec_headers") or {}).get("summary", {})
    for k,hname in [("x-frame-options","X-Frame-Options"),("x-content-type-options","X-Content-Type-Options"),("csp","Content-Security-Policy")]:
        if sh.get(k) == "absent": notes.append(f"{hname} not set.")
    open_ports=set((d.get("ports") or {}).get("open",[]) or [])
    risky={21:"FTP",23:"Telnet",25:"SMTP",110:"POP3",143:"IMAP",3389:"RDP",445:"SMB"}
    found=[f"{p}/{risky[p]}" for p in risky if p in open_ports]
    if found: notes.append("Legacy/insecure services exposed: " + ", ".join(found))
    return notes

def write_report_html(path: str, data: dict, meta: dict) -> None:
    def kv_table(rows: list) -> str:
        tr="".join([f"<tr><th>{_html_escape(k)}</th><td>{_html_escape(v)}</td></tr>" for k,v in rows if v is not None])
        return f'<table class="kv">{tr}</table>'
    def list_html(items: list, limit: int = None) -> str:
        if limit: items = items[:limit] + (["…"] if len(items) > limit else [])
        lis="".join([f"<li>{_html_escape(str(i))}</li>" for i in items]); return f"<ul>{lis}</ul>"
    def table2(headers: list, rows: list, limit: int = None) -> str:
        if limit and len(rows)>limit: rows = rows[:limit]; rows.append(["…"]*len(headers))
        th="".join([f"<th>{_html_escape(h)}</th>" for h in headers])
        tr="".join(["<tr>"+"".join([f"<td>{_html_escape(str(c) if c is not None else '')}</td>" for c in r])+"</tr>" for r in rows])
        return f'<table class="grid"><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table>'

    subs = data.get("subdomains") or []
    open_ports=(data.get("ports") or {}).get("open",[]) or []
    pages=(data.get("crawl") or {}).get("pages",[]) or []
    highlights=_derive_highlights(data)

    title=(meta.get("project") or f"Enumeration Report for {data.get('host')}")
    ts=_fmt_dt(data.get("ts", time.time()))

    cover=f"""
    <div class="cover">
      <h1>{_html_escape(title)}</h1>
      <p><b>Date:</b> {ts}</p>
      <p><b>Scope:</b> {_html_escape(meta.get("scope") or f"Target: {data.get('target')}")}</p>
    </div>"""

    exec_kv = kv_table([
        ("Target", data.get("target")),
        ("Resolved Host", data.get("host")),
        ("Open TCP Ports", str(len(open_ports))),
        ("Crawled Pages", str(len(pages))),
        ("HTTP/2", str(((data.get("web_fingerprint") or {}).get("http2") or {}).get("negotiated"))),
    ])
    exec_high = list_html(highlights or ["No immediate concerns auto-detected."])
    exec_html = f"""<div class="two-col"><div>{exec_kv}</div><div><h3>Highlights</h3>{exec_high}</div></div>"""

    pr=data.get("ports") or {}; port_rows=[[p, (pr.get("banners") or {}).get(str(p),"")[:120]] for p in sorted(pr.get("open", []))]
    ports_html = table2(["Port","Banner (truncated)"], port_rows, limit=200)

    probe=data.get("http_probe") or {}; hdrs=probe.get("headers") or {}
    def kv(rows): return "<br>".join([f"<b>{_html_escape(k)}</b>: {_html_escape(str(v))}" for k,v in rows])
    hdr_kv = kv([("URL", probe.get("target_url")), ("Status", str(probe.get("status"))), ("Final URL", probe.get("final_url")), ("HSTS", str(probe.get("hsts")))])
    hdr_list = list_html([f"{k}: {v}" for k,v in list(hdrs.items())[:30]])
    wf=data.get("web_fingerprint") or {}; techs=wf.get("tech") or []
    tech_list = list_html([f"{t.get('name')} ({t.get('confidence',0)})" for t in techs])
    sech = wf.get("sec_headers") or {}
    sech_tbl = table2(["Header","Value/Present"], [[k, (sech.get(k) or 'absent' if (sech.get("summary") or {}).get(k)=='absent' else (sech.get(k) or ''))] for k in ("csp","x-frame-options","x-content-type-options","referrer-policy","permissions-policy","hsts")])

    style = """
    <style>
      body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;line-height:1.45;margin:40px;color:#222}
      h1,h2,h3{margin:0.6em 0 0.3em}
      .cover{padding:24px;border:1px solid #ddd;border-radius:8px;margin-bottom:24px}
      .two-col{display:flex;gap:24px}
      .two-col>div{flex:1}
      table.kv{border-collapse:collapse;width:100%;margin:8px 0}
      table.kv th{background:#f6f6f6;text-align:left;padding:6px;border:1px solid #ddd;width:220px}
      table.kv td{padding:6px;border:1px solid #ddd}
      table.grid{border-collapse:collapse;width:100%;margin:8px 0}
      table.grid th, table.grid td{border:1px solid #ddd;padding:6px;vertical-align:top}
      section{margin:28px 0}
      a{color:#1355cc;text-decoration:none} a:hover{text-decoration:underline}
    </style>"""

    html=f"""<!doctype html><html><head><meta charset="utf-8"><title>{_html_escape(title)}</title>{style}</head>
    <body>
      {cover}
      {_html_section("Executive Summary", exec_html, "exec")}
      {_html_section("Ports & Services", ports_html, "ports")}
      {_html_section("Web Surface", "<h3>HTTP Probe</h3><p>"+hdr_kv+"</p><h4>Response headers</h4>"+hdr_list+"<h3>Detected Technologies</h3>"+tech_list+"<h3>Security Headers</h3>"+sech_tbl, "web")}
    </body></html>"""
    with open(path,"w",encoding="utf-8") as f: f.write(html)
