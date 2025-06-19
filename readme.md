# AI-Powered Web Exploit Engine - Athena (v1.4-dynamic)

## Introduction  
AI-powered, ultra-comprehensive web vulnerability scanner and fuzzer that automatically discovers and tests every endpoint—static links, dynamic SPA routes, REST/GraphQL APIs, JS bundles, uploads, WASM, XXE, deserialization, smuggling, prototype-pollution, and more, across any modern website or web app.

---

## Download the PDF here
https://cyberzeus.pk/Athena_AI_Powered_Post_Exploitation_&_C2_Framework_Technical_Manual.pdf

---


## New in v1.4-dynamic

- **HTTP/2 Smuggling** (`--http2`)  
  Detect “CL→TE” and “TE→CL” ordering attacks over HTTP/2 (placeholder for Hyper/HTTPX).  
- **Trailer Injection** (`--trailer`)  
  Abuse chunked trailers (e.g. `0\r\nFlavor: CHEESE\r\n\r\n`) to smuggle headers.  
- **HTTP Parameter Pollution** (`--hpp`)  
  Duplicate query parameters (`?id=1&id=2`) to confuse parsers.  
- **SSRF Polyglot** (`--ssrf`)  
  Test `http://`, `gopher://`, `dict://` schemes for server-side requests.  
- **GraphQL Mutation** (`--gmut`)  
  Blind mutation probe (`mutation { __typename }`) alongside introspection.  
- **WebSocket Fuzzing** (`--ws`)  
  Hooks `window.WebSocket`, auto-discovers wss/ws endpoints, sends ping/pong.  
- **SSE Injection** (`--sse`)  
  Hooks `EventSource`, listens for first `data:` event.  
- **CSP Bypass** (`--csp`)  
  Injects `<script src=…>` via query param to bypass `script-src`.  
- **CORS Misconfiguration** (`--cors`)  
  Checks `Access-Control-Allow-Origin: *` on preflight.  
- **Service Worker Abuse** (`--sw`)  
  Scans `/sw.js` for `importScripts()` hooks.  
- **JWT “alg=none” Tampering** (`--jwt`)  
  Crafts unsigned bearer token header+payload with `alg: none`.  
- **SPA Hash-Route XSS** (`--spa`)  
  Injects into `#/<param>=…` routes for client-side XSS.  
- **Sync Fallback Mode** (`--sync`)  
  Uses `requests` + `ThreadPoolExecutor` when async is unavailable.  
- **JS-Bundle Parsing** enhancements  
  Now recognizes `fetch()`, `axios.get/post()`, `WebSocket()` and `EventSource()` URIs.  
- **Playwright Hooks**  
  Intercepts XHR/fetch, plus WebSocket/SSE creation in-page.  

---

## Invented Variants & Techniques

- **HTTP/2 Trailer Injection** – abuse chunked trailer fields for header smuggling  
- **HPP** – duplicate parameter pollution in URL queries  
- **SSRF Polyglot** – `gopher://`, `dict://` SSRF vectors  
- **WebSocket Hijack** – hook `window.WebSocket` to auto-discover and fuzz WS endpoints  
- **SSE Trap** – hook `EventSource`, capture first `data:` event  
- **GraphQL Mutation** – blind mutation introspection beyond `__schema`  
- **Polyglot Uploads** – JPEG+ZIP containers with server-side code payload  
- **WASM Fuzz** – minimal Wasm binaries to trigger parser edge cases  
- **AI-XSS Mutation** –  mutation of `<script>alert()</script>` variants  
- **Prompt Injection** – LLM prompt attacks via form/JSON parameters  
- **Prototype Pollution** – nested `__proto__` overrides and `constructor.prototype` injection  
- **Smuggling Variants** – both “CL then TE” and “TE then CL” orderings  
- **JWT None** – unsigned token abuse (`alg=none`)  
- **CSP & CORS** – inline script injection and wildcard origin checks  
- **Service Worker** – scanning for `importScripts()` in SW files  

---

## Features

- **Static + Dynamic Crawling** (`--render`)  
  Follows `<a>`/`<form>` plus headless-Chromium to trap XHR, Fetch, GraphQL, WS & SSE calls.  
- **JS-Bundle Parsing** (`--jsparse`)  
  Regex-scans external `.js` bundles for hidden endpoints.  
- **Custom Wordlist Routes** (`--routes`)  
  Brute-forces user-supplied paths (admin panels, health checks, etc.).  
- **AI-Driven Mutation** (`--ai`)  
  -powered XSS payload diversification.  
- **Comprehensive Modules**  
  XXE, JSON deserialization, prototype-pollution, HTTP smuggling (sync & async), GraphQL introspection & mutations, prompt injection, polyglot uploads, WASM parsing, SSRF, HPP, CSP/CORS, Service Worker, JWT, SPA XSS, WebSocket, SSE.  
- **Stealth & Fallbacks**  
  Alternate content-types, GET/POST methods, secondary endpoints, sync fallback mode, jitter delays.  
- **Highly Configurable**  
  Thread pool size, page limits, debug logging, DNSLog beaconing, smart HTTPS⇄HTTP, rotating headers.

---

## Installation

```bash
git clone https://github.com/haroonawanofficial/mwvu.git
cd mwvu
pip install -r requirements.txt   # requests, bs4, fake-useragent, playwright, transformers, torch
playwright install                # if using --render
```

# Async scan (default)
python athena.py -u https://target.com --all --render --jsparse --routes list.txt --ai --debug

# Sync fallback
python athena.py -u https://target.com --sync --all

# Select modules
python athena.py -u https://target.com --xxe --deser --pollute --smuggle

# New tests
python athena.py -u https://target.com --http2 --trailer --hpp --ssrf --gmut --ws --sse --csp --cors --sw --jwt --spa
