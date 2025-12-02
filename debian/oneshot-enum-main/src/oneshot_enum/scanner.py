# scanner.py — core enumeration (essentials + AD ports included)
from __future__ import annotations
import asyncio, importlib, ipaddress, json, os, re, time, hashlib, socket, ssl
from types import SimpleNamespace
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone

CFG = SimpleNamespace(
    TIMEOUT=10.0,
    CONCURRENCY=200,
    USER_AGENT="oneshot-enum/0.1",
    CACHE_DIR=".cache",
    CACHE_TTL=60*60*24,
    BUDGET_REQUESTS=10000,
    BUDGET_TIME=60*15,
    DNS_LEVEL="min",
    DNS_SOURCE="system",
    PUBLIC_RESOLVERS=["1.1.1.1","8.8.8.8"],
    CRAWL_DEPTH=1,
    MAX_PAGES=80,
    SCAN_TCP=True,
    SCAN_PORTS="popular",
    SCAN_RATE=200,
    CONN_TIMEOUT=2.0,
    PROBE_BANNERS=True,
    TLS_DETAIL=True,
    TLS_ALPN=True,
    TLS_HSTS=True,
    SUBS_PASSIVE=True,
    SUBS_PERMS=True,
    WEB_FP=True, JS_SCAN=False, ROBOTS=True, SITEMAP=True,
    EMAIL_POSTURE=False, DNSSEC=False,
    CLOUD_BUCKETS=False, CDN_WAF=True,
    ASN_EXPAND=False,
    UDP=False, UDP_PORTS="53,123,161,1900,5353",
    SERVICE_DEEP=True, DIR_HUNT=True,
    JARM=False, NMAP=False, NMAP_ARGS=None,
)

REQUIRED = {
    "httpx":"httpx", "bs4":"beautifulsoup4", "lxml":"lxml",
    "tldextract":"tldextract", "whois":"python-whois", "waybackpy":"waybackpy",
    "rich":"rich", "yaml":"PyYAML", "ipwhois":"ipwhois", "mmh3":"mmh3",
    "dns":"dnspython", "cryptography":"cryptography",
}
MOD = SimpleNamespace()
START_TS = time.time()
COUNTS = SimpleNamespace(requests=0)
SEM_GLOBAL: Optional[asyncio.Semaphore] = None

def ensure_requirements():
    missing=[]
    for mod, pkg in REQUIRED.items():
        try: importlib.import_module(mod)
        except Exception: missing.append(pkg)
    if missing:
        raise RuntimeError("Missing packages: " + ", ".join(sorted(set(missing))))

def load_libs():
    MOD.httpx = importlib.import_module("httpx")
    MOD.bs4 = importlib.import_module("bs4"); MOD.BeautifulSoup = MOD.bs4.BeautifulSoup
    MOD.tldextract = importlib.import_module("tldextract")
    MOD.whois = importlib.import_module("whois")
    MOD.waybackpy = importlib.import_module("waybackpy")
    MOD.rich = importlib.import_module("rich"); MOD.console = MOD.rich.console.Console()
    MOD.yaml = importlib.import_module("yaml")
    MOD.ipwhois = importlib.import_module("ipwhois")
    MOD.mmh3 = importlib.import_module("mmh3")
    MOD.cryptography = importlib.import_module("cryptography")
    MOD.x509 = importlib.import_module("cryptography.x509")
    MOD.hashes = importlib.import_module("cryptography.hazmat.primitives.hashes")
    MOD.datetime = importlib.import_module("datetime")
    MOD.dns = importlib.import_module("dns")
    MOD.dns_resolver = importlib.import_module("dns.resolver")

def ensure_cache():
    if CFG.CACHE_DIR and not os.path.isdir(CFG.CACHE_DIR):
        os.makedirs(CFG.CACHE_DIR, exist_ok=True)

def now() -> float: return time.time()
def host_for(target: str) -> str:
    h = urlparse(norm_url(target)).hostname
    return h or target
def is_ip(s: str) -> bool:
    try: ipaddress.ip_address(s); return True
    except ValueError: return False
def norm_url(t: str) -> str:
    if re.match(r"^https?://", t, re.I): return t
    if is_ip(t): return f"http://{t}"
    return f"http://{t}"
def to_https(url: str) -> str:
    return re.sub(r"^http://", "https://", url, flags=re.I)
def with_base(path: str, base_url: str) -> str:
    return urljoin(base_url + ("" if base_url.endswith("/") else "/"), path)

async def budget_gate():
    if CFG.BUDGET_TIME and (now()-START_TS)>CFG.BUDGET_TIME:
        raise RuntimeError("Budget time exceeded")
    if CFG.BUDGET_REQUESTS and COUNTS.requests >= CFG.BUDGET_REQUESTS:
        raise RuntimeError("Budget requests exceeded")

async def _http_req(url: str, method="GET", verify=True, allow_redirects=True):
    await budget_gate()
    headers={"User-Agent": CFG.USER_AGENT}
    timeout=MOD.httpx.Timeout(CFG.TIMEOUT)
    async with SEM_GLOBAL:
        async with MOD.httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=allow_redirects, verify=verify, trust_env=False) as c:
            COUNTS.requests += 1
            if method=="HEAD": return await c.head(url)
            return await c.get(url)

def _make_resolver_sync():
    r = MOD.dns_resolver.Resolver(configure=(CFG.DNS_SOURCE=="system"))
    r.lifetime = CFG.TIMEOUT; r.timeout = CFG.TIMEOUT
    return r

def enum_dns_sync(target: str) -> Dict:
    h = host_for(target)
    out = {"host":h, "records":{}, "errors":[]}
    try:
        infos = socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP)
        a, aaaa = set(), set()
        for _,_,_,_,socka in infos:
            ip = socka[0]
            try:
                obj = ipaddress.ip_address(ip)
                (a if obj.version==4 else aaaa).add(ip)
            except ValueError: pass
        if a: out["records"]["A"]=sorted(a)
        if aaaa: out["records"]["AAAA"]=sorted(aaaa)
    except Exception as e: out["errors"].append(f"A/AAAA: {e}")
    return out

async def enum_dns(target: str) -> Dict:
    return await asyncio.to_thread(enum_dns_sync, target)

async def probe_http(target: str) -> Dict:
    base_http = norm_url(target)
    base_https = to_https(base_http)
    attempts = [("HEAD", base_http, True), ("GET", base_http, True), ("HEAD", base_https, False), ("GET", base_https, False)]
    res={"target_url":base_http,"status":None,"headers":{},"final_url":None,"hsts":False,"error":None,"attempt":None,"error_chain":[]}
    for method,url,verify in attempts:
        try:
            r = await _http_req(url, method=method, verify=verify, allow_redirects=True)
            res.update({"status":r.status_code,"headers":dict(r.headers),"final_url":str(r.url),"attempt":{"method":method,"url":url,"verify":verify}})
            res["hsts"]=bool(r.headers.get("strict-transport-security"))
            res["target_url"]=url
            return res
        except Exception as e:
            res["error_chain"].append({"method":method,"url":url,"verify":verify,"error":str(e)})
    res["error"]=res["error_chain"][-1]["error"] if res["error_chain"] else "unknown"
    return res

async def tls_fingerprint_async(host: str, port: int=443) -> Dict:
    out={"host":host,"port":port,"alpn":None,"cert":None,"error":None,"tls_version":None,"cipher":None}
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        try: ctx.set_alpn_protocols(["h2","http/1.1"])
        except Exception: pass
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=CFG.CONN_TIMEOUT)
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                try: out["alpn"] = ssl_obj.selected_alpn_protocol()
                except Exception: pass
                try:
                    out["tls_version"] = ssl_obj.version()
                    c = ssl_obj.cipher()
                    if c: out["cipher"] = {"name": c[0], "protocol": c[1], "bits": c[2]}
                except Exception: pass
                der = ssl_obj.getpeercert(binary_form=True)
                if der and CFG.TLS_DETAIL:
                    cert = MOD.x509.load_der_x509_certificate(der)
                    nb = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
                    na = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
                    if getattr(nb, "tzinfo", None) is None: nb = nb.replace(tzinfo=timezone.utc)
                    if getattr(na, "tzinfo", None) is None: na = na.replace(tzinfo=timezone.utc)
                    out["cert"] = {
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "notBefore": nb.strftime("%b %d %H:%M:%S %Y GMT"),
                        "notAfter":  na.strftime("%b %d %H:%M:%S %Y GMT"),
                    }
        finally:
            try: writer.close(); await writer.wait_closed()
            except Exception: pass
    except Exception as e:
        out["error"]=str(e)
    return out

POPULAR_PORTS=[21,22,23,25,53,80,110,111,123,135,137,138,139,143,161,179,389,443,445,465,587,631,636,993,995,1433,1521,2049,2375,2380,2480,3000,3306,3389,3478,3690,4000,4100,4200,4222,4369,4443,4500,4567,5000,5060,5222,5432,5555,5601,5672,5900,5985,5986,6379,6443,6667,7071,7080,7200,7474,7547,7634,7777,8000,8008,8010,8080,8081,8088,8100,8161,8181,8200,8443,8500,8530,8531,8545,8600,8671,8686,8880,8888,9000,9001,9042,9092,9100,9200,9300,9418,9443,9494,9500,9600,9800,10000,11211,15672,27017,27018,27019,28017]
def parse_ports(spec: str) -> List[int]:
    if spec=="popular": return POPULAR_PORTS
    out=[]
    for tok in re.split(r"[,\s]+", spec):
        if not tok: continue
        if "-" in tok:
            a,b=tok.split("-",1); out.extend(range(int(a), int(b)+1))
        elif tok.isdigit(): out.append(int(tok))
    return sorted(set([p for p in out if 1<=p<=65535]))

async def tcp_connect(host: str, port: int):
    try:
        async with SEM_GLOBAL:
            fut = asyncio.open_connection(host, port)
            r,w = await asyncio.wait_for(fut, timeout=CFG.CONN_TIMEOUT)
            try: w.close()
            except Exception: pass
            return port, True
    except Exception:
        return port, False

async def banner_peek(host: str, port: int) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=CFG.CONN_TIMEOUT)
        to_send=None
        if port in (80,8080,8000,8888,8443):
            to_send = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {CFG.USER_AGENT}\r\n\r\n"
        elif port in (21,22):
            to_send=b"\n"
        if to_send: writer.write(to_send if isinstance(to_send,(bytes,bytearray)) else to_send.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=1.5)
        writer.close()
        return data.decode(errors="ignore").strip() if data else None
    except Exception:
        return None

async def scan_ports(host: str, ports: List[int], banners: bool) -> Dict:
    res={"host":host,"open":[],"banners":{}}
    tasks=[tcp_connect(host,p) for p in ports]
    for i in range(0,len(tasks), CFG.SCAN_RATE):
        chunk = tasks[i:i+CFG.SCAN_RATE]
        for p,ok in await asyncio.gather(*chunk):
            if ok: res["open"].append(p)
    if banners and res["open"]:
        results = await asyncio.gather(*[banner_peek(host,p) for p in res["open"]])
        for p,b in zip(res["open"], results):
            if b: res["banners"][str(p)] = b
    return res

def audit_security_headers(headers: Dict[str, str]) -> Dict[str, Optional[str]]:
    H = {k.lower(): v for k, v in (headers or {}).items()}
    out = {
        "csp": H.get("content-security-policy"),
        "x-frame-options": H.get("x-frame-options"),
        "x-content-type-options": H.get("x-content-type-options"),
        "referrer-policy": H.get("referrer-policy"),
        "permissions-policy": H.get("permissions-policy"),
        "hsts": H.get("strict-transport-security"),
    }
    out["summary"] = {k: ("present" if v else "absent") for k, v in out.items() if k != "summary"}
    return out

def web_fingerprint(text: str, headers: Dict[str,str]) -> List[Dict]:
    tech=[]; H={k.lower():v for k,v in headers.items()}
    if "server" in H: tech.append({"name":f"Server:{H['server']}", "confidence":0.6})
    if "x-powered-by" in H: tech.append({"name":f"X-Powered-By:{H['x-powered-by']}", "confidence":0.9})
    if "wp-content" in text: tech.append({"name":"WordPress","confidence":0.95})
    if "data-reactroot" in text or "ReactDOM" in text: tech.append({"name":"React","confidence":0.6})
    if "ng-version" in text: tech.append({"name":"Angular","confidence":0.9})
    if "Next.js" in text or "__NEXT_DATA__" in text: tech.append({"name":"Next.js","confidence":0.9})
    return tech

async def crawl(start: str, depth: int, max_pages: int, verify: bool) -> Dict:
    start_url = norm_url(start); host = urlparse(start_url).hostname
    out={"start":start_url,"depth":depth,"visited":[],"pages":[],"errors":[]}
    if not host: return out
    q=[(start_url,0)]; seen=set()
    async def fetch(u: str):
        try:
            r = await _http_req(u, "GET", verify=verify, allow_redirects=True)
            ctype=r.headers.get("content-type","")
            text = r.text if "text/html" in (ctype or "").lower() else ""
            title = ""
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(text, "lxml") if text else None
                title = (soup.title.string.strip() if soup and soup.title and soup.title.string else "")
                links=[]
                if soup:
                    for a in soup.find_all("a", href=True):
                        links.append(urljoin(str(r.url), a["href"].strip()))
            except Exception:
                links=[]
            page={"url":str(r.url),"status":r.status_code,"title":title,"headers":dict(r.headers)}
            return page, links
        except Exception as e:
            out["errors"].append(f"{u}: {e}"); return None, []
    while q and len(seen) < max_pages:
        url,d = q.pop(0)
        if url in seen or d>depth: continue
        seen.add(url)
        page, links = await fetch(url)
        if page: out["pages"].append(page)
        for link in links:
            if len(seen)+len(q)>=max_pages: break
            u=urlparse(link)
            if u.scheme in ("http","https") and u.hostname==host and link not in seen:
                q.append((link, d+1))
    out["visited"]=sorted(seen); return out

async def robots_fetch_url(base_url: str, verify: bool) -> Dict:
    try:
        r = await _http_req(url=with_base("/robots.txt", base_url), method="GET", verify=verify)
        disallow=re.findall(r'^\s*Disallow:\s*(\S+)', r.text or "", re.I|re.M)
        sitemaps=re.findall(r'^\s*Sitemap:\s*(\S+)', r.text or "", re.I|re.M)
        return {"url":str(r.url),"status":r.status_code,"disallow":disallow[:100],"sitemaps":sitemaps[:50]}
    except Exception as e: return {"error":str(e)}

async def sitemap_fetch_url(base_url: str, verify: bool) -> Dict:
    try:
        r = await _http_req(url=with_base("/sitemap.xml", base_url), method="GET", verify=verify)
        urls=re.findall(r"<loc>([^<]+)</loc>", r.text or "", re.I)
        return {"url":str(r.url), "status":r.status_code, "count":len(urls), "sample":urls[:50]}
    except Exception as e: return {"error":str(e)}

async def run_all(target: str, ports_spec: str) -> Dict:
    ensure_requirements(); load_libs(); ensure_cache()
    global SEM_GLOBAL; SEM_GLOBAL = asyncio.Semaphore(CFG.CONCURRENCY)
    h=host_for(target)

    dns_task = asyncio.create_task(enum_dns(target))
    probe_res = await probe_http(target)
    base_url = probe_res.get("final_url") or probe_res.get("target_url") or norm_url(target)
    verify = bool((probe_res.get("attempt") or {}).get("verify", True))

    tls_res=None
    try:
        pu=urlparse(base_url)
        if pu.scheme=="https":
            port = pu.port or 443
            host_tls = pu.hostname or h
            tls_res = await tls_fingerprint_async(host_tls, port)
    except Exception: tls_res=None

    crawl_task   = asyncio.create_task(crawl(base_url, depth=CFG.CRAWL_DEPTH, max_pages=CFG.MAX_PAGES, verify=verify))
    robots_task  = asyncio.create_task(robots_fetch_url(base_url, verify))
    sitemap_task = asyncio.create_task(sitemap_fetch_url(base_url, verify))

    ports = parse_ports(ports_spec) if CFG.SCAN_TCP else []
    scan_task = asyncio.create_task(scan_ports(h, ports, CFG.PROBE_BANNERS)) if ports else asyncio.create_task(asyncio.sleep(0, result={"host":h,"open":[]}))

    dns_res, crawl_res, robots_res, sitemap_res, scan_res = await asyncio.gather(dns_task, crawl_task, robots_task, sitemap_task, scan_task)

    webfp={}
    try:
        r0 = await _http_req(base_url, "GET", verify=verify)
        webfp["tech"] = web_fingerprint(r0.text, dict(r0.headers)) if CFG.WEB_FP else []
        webfp["sec_headers"] = audit_security_headers(dict(r0.headers))
    except Exception as e:
        webfp["error"]=str(e)

    return {
        "target": target, "host": h,
        "config": {"scan_ports": ports_spec, "timeout": CFG.TIMEOUT},
        "dns": dns_res, "http_probe": probe_res, "tls": tls_res,
        "crawl": crawl_res, "web_fingerprint": webfp,
        "robots": robots_res, "sitemap": sitemap_res,
        "ports": scan_res,
        "ts": time.time(),
    }
