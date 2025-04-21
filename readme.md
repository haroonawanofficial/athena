# AI-Powered Modern Web Vulnerabilities Scaner

## Introduction  
AI‑powered, ultra‑comprehensive web vulnerability scanner and fuzzer that automatically discovers and tests every endpoint—static links, dynamic SPA routes, REST/GraphQL APIs, JS bundles, uploads, WASM, XXE, deserialization, smuggling, prototype‑pollution, and more, across any modern website or web app.

## Features
- **Static + Dynamic Crawling**  
  Follows `<a>` and `<form>` links, plus headless‑Chromium via Playwright (`--render`) to trap all XHR/Fetch/GraphQL calls.  
- **JS‑Bundle Parsing** (`--jsparse`)  
  Regex‑scans external `.js` files for hidden endpoints.  
- **Custom Wordlist Routes** (`--routes`)  
  Brute‑forces user‑supplied paths (admin panels, health checks, etc.).  
- **AI‑Driven** (`--ai`)  
  Uses XSS payloads on the fly.  
- **Comprehensive Vulnerability Modules**  
  XXE, JSON deserialization, prototype‑pollution, HTTP smuggling, GraphQL introspection, prompt injection, polyglot file upload, WASM parsing—all with multi‑layer fallbacks.  
- **Stealth & Fallbacks**  
  Alternate content‑types, methods (GET/POST), secondary endpoints, unreported variants for maximum coverage.  
- **Highly Configurable**  
  Thread pool size, page limits, debug logging, DNSLog beaconing, smart HTTPS⇄HTTP, rotating headers.

## Installation
```bash
git clone https://github.com/haroonawanofficial/mwvu.git
cd mwvu
pip install -r requirements.txt  # includes requests, bs4, fake-useragent, playwright, transformers, torch
playwright install             # if using --render
