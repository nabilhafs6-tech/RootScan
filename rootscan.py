#!/usr/bin/env python3
r"""
    ____              __  _____
   / __ \____  ____  / /_/ ___/________ _____
  / /_/ / __ \/ __ \/ __/\__ \/ ___/ __ `/ __ \
 / _, _/ /_/ / /_/ / /_ ___/ / /__/ /_/ / / / /
/_/ |_|\____/\____/\__//____/\___/\__,_/_/ /_/

RootScan — deep, respectful, full-stack web security scanner.
Crawls to the roots: pages, headers, TLS, exposure, CORS, cookies, forms.

⚠  AUTHORIZED USE ONLY — scan only assets you own or have written
   permission to test. You are responsible for how you use this tool.

Zero dependencies: pure Python 3.8+ standard library.
"""

import argparse
import datetime
import gzip
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from html.parser import HTMLParser

VERSION = "1.0.0"
UA = f"RootScan/{VERSION} (+authorized security testing)"
MAX_BODY = 1_500_000
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 0}

# ---------------------------------------------------------------- console ui

class C:
    on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    R = "\033[91m" if on else ""
    G = "\033[92m" if on else ""
    Y = "\033[93m" if on else ""
    B = "\033[94m" if on else ""
    M = "\033[95m" if on else ""
    DIM = "\033[2m" if on else ""
    BOLD = "\033[1m" if on else ""
    X = "\033[0m" if on else ""

SEV_COLOR = {"CRITICAL": C.M, "HIGH": C.R, "MEDIUM": C.Y, "LOW": C.B, "INFO": C.DIM}

def banner():
    print(f"""{C.G}{C.BOLD}
    ____              __  _____
   / __ \\____  ____  / /_/ ___/________ _____
  / /_/ / __ \\/ __ \\/ __/\\__ \\/ ___/ __ `/ __ \\
 / _, _/ /_/ / /_/ / /_ ___/ / /__/ /_/ / / / /
/_/ |_|\\____/\\____/\\__//____/\\___/\\__,_/_/ /_/
{C.X}{C.DIM}  v{VERSION} · zero-dependency full-stack web scanner{C.X}
{C.Y}  ⚠  Authorized testing only — you own it, or you have written permission.{C.X}
""")

def section(title):
    print(f"\n{C.BOLD}{C.G}─── {title} {'─' * max(4, 62 - len(title))}{C.X}")

def ok(msg):
    print(f"  {C.G}[ OK ]{C.X} {msg}")

def finding_line(f):
    col = SEV_COLOR[f["severity"]]
    print(f"  {col}{C.BOLD}[{f['severity']:>8}]{C.X} {C.BOLD}{f['title']}{C.X}")
    print(f"           {C.DIM}at {f['url']}{C.X}")
    if f.get("detail"):
        print(f"           {f['detail']}")
    if f.get("fix"):
        print(f"           {C.DIM}↳ fix: {f['fix']}{C.X}")

# ---------------------------------------------------------------- findings

FINDINGS = []

def add_finding(severity, check, title, url, detail="", fix=""):
    FINDINGS.append({
        "severity": severity, "check": check, "title": title,
        "url": url, "detail": detail, "fix": fix,
    })

def grade_and_score():
    penalty = min(100, sum(SEV_WEIGHT[f["severity"]] for f in FINDINGS))
    score = 100 - penalty
    grade = ("A" if score >= 90 else "B" if score >= 75 else
             "C" if score >= 60 else "D" if score >= 40 else "F")
    return score, grade

# ---------------------------------------------------------------- http layer

def fetch(url, method="GET", headers=None, timeout=10):
    """Minimal, careful HTTP client. Returns a result dict; never raises."""
    hdrs = {"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip", "Accept-Language": "en-US,en;q=0.9"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, method=method, headers=hdrs)
    ctx = ssl.create_default_context()
    out = {"url": url, "status": None, "headers": {}, "raw": None,
           "body": b"", "final": url, "err": None}
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read(MAX_BODY)
            if "gzip" in (r.headers.get("Content-Encoding") or ""):
                try:
                    raw = gzip.decompress(raw)
                except OSError:
                    pass
            out.update(status=r.status, raw=r.headers,
                       headers={k.lower(): v for k, v in r.headers.items()},
                       body=raw, final=r.geturl())
    except urllib.error.HTTPError as e:
        try:
            body = e.read(300_000)
        except Exception:
            body = b""
        out.update(status=e.code, raw=e.headers,
                   headers={k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
                   body=body, final=url)
    except Exception as e:  # noqa: BLE001 - network is chaos, stay alive
        out["err"] = f"{type(e).__name__}: {e}"
    return out

def text_of(result):
    try:
        return result["body"].decode("utf-8", errors="ignore")
    except Exception:
        return ""

# ---------------------------------------------------------------- html parse

class PageParser(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links, self.forms, self.comments = [], [], []
        self.meta_generator = None
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(urllib.parse.urljoin(self.base, a["href"]))
        elif tag == "form":
            self._form = {"action": urllib.parse.urljoin(self.base, a.get("action") or self.base),
                          "method": (a.get("method") or "GET").upper(), "inputs": []}
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append(a)
        elif tag == "meta" and a.get("name", "").lower() == "generator":
            self.meta_generator = a.get("content", "")

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_comment(self, data):
        if data and len(data) < 500:
            self.comments.append(data.strip())

ASSET_EXT = re.compile(r"\.(css|js|mjs|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|pdf|"
                       r"zip|tar|gz|mp4|webm|mp3|wav|avif|map)(\?|#|$)", re.I)

def normalize(url):
    p = urllib.parse.urlsplit(url)
    p = p._replace(fragment="", scheme=p.scheme.lower(),
                   netloc=p.netloc.lower())
    return urllib.parse.urlunsplit(p)

# ---------------------------------------------------------------- crawler

def crawl(start, opts):
    parsed = urllib.parse.urlsplit(start)
    host = parsed.hostname or ""
    seen, queue, pages = set(), deque([(start, 0)]), []
    deadline = time.monotonic() + opts.max_time
    first = True

    while queue and len(pages) < opts.max_pages and time.monotonic() < deadline:
        url, depth = queue.popleft()
        url = normalize(url)
        if url in seen:
            continue
        seen.add(url)
        if not first and opts.delay:
            time.sleep(opts.delay)
        first = False

        r = fetch(url, timeout=opts.timeout)
        if r["err"]:
            print(f"  {C.DIM}[err ] {url} — {r['err']}{C.X}" if opts.verbose else "", end="")
            continue

        final_host = urllib.parse.urlsplit(r["final"]).hostname or host
        if depth == 0:
            host = final_host  # follow www/http→https moves for scoping

        ct = r["headers"].get("content-type", "")
        html = text_of(r) if ("html" in ct or "xml" in ct or not ct) else ""
        pages.append({"url": url, "final": r["final"], "status": r["status"],
                      "content_type": ct.split(";")[0], "depth": depth})
        print(f"  {C.DIM}[{r['status']}] depth={depth} {url}{C.X}")

        if depth < opts.depth and html:
            pp = PageParser(r["final"])
            try:
                pp.feed(html)
            except Exception:
                pass
            for link in pp.links:
                sp = urllib.parse.urlsplit(link)
                if sp.scheme not in ("http", "https"):
                    continue
                if sp.hostname != host:
                    continue
                if ASSET_EXT.search(sp.path):
                    continue
                link = normalize(link)
                if link not in seen:
                    queue.append((link, depth + 1))
            pages[-1]["_parser"] = pp
            pages[-1]["_html"] = html
            pages[-1]["_headers"] = r["headers"]
            pages[-1]["_raw_headers"] = r["raw"]
    return pages

# ---------------------------------------------------------------- tls

def tls_check(url):
    if not url.startswith("https"):
        add_finding("MEDIUM", "tls", "Plain HTTP — no transport encryption", url,
                    "Traffic (logins, cookies, sessions) travels in cleartext.",
                    "Serve everything over HTTPS and redirect HTTP → HTTPS.")
        return
    host = urllib.parse.urlsplit(url).hostname
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                proto = s.version()
        exp = ssl.cert_time_to_seconds(cert["notAfter"])
        days = int((exp - time.time()) // 86400)
        issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "?")
        ok(f"TLS {proto} · cert by {issuer} · expires in {days}d")
        if days < 0:
            add_finding("HIGH", "tls", "Certificate EXPIRED", url,
                        f"Expired {abs(days)} days ago.", "Renew the certificate immediately.")
        elif days < 14:
            add_finding("HIGH", "tls", "Certificate expiring very soon", url,
                        f"Only {days} days left.", "Renew the certificate now.")
        elif days < 30:
            add_finding("MEDIUM", "tls", "Certificate expiring soon", url,
                        f"{days} days left.", "Schedule renewal (automate with ACME/Let's Encrypt).")
        if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            add_finding("HIGH", "tls", f"Obsolete protocol negotiated: {proto}", url,
                        "Legacy TLS is broken (POODLE, BEAST).",
                        "Disable TLS < 1.2; prefer TLS 1.3.")
        elif proto == "TLSv1.2":
            ok("TLS 1.2 negotiated (acceptable — TLS 1.3 preferred)")
        elif proto == "TLSv1.3":
            ok("TLS 1.3 negotiated")
    except ssl.SSLCertVerificationError as e:
        add_finding("HIGH", "tls", "Certificate validation failed", url, str(e),
                    "Fix the certificate chain / hostname mismatch.")
    except Exception as e:  # noqa: BLE001
        print(f"  {C.DIM}(tls check skipped: {e}){C.X}")

# ---------------------------------------------------------------- headers

HEADER_RULES = [
    ("content-security-policy", "MEDIUM", "Missing Content-Security-Policy",
     "No CSP — injected scripts have free rein.",
     "Add a strict CSP, e.g. default-src 'self'; object-src 'none'; base-uri 'self'."),
    ("strict-transport-security", "MEDIUM", "Missing HSTS",
     "Users can be SSL-stripped on first visit.",
     "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."),
    ("x-frame-options", "MEDIUM", "Clickjacking protection missing",
     "No X-Frame-Options and no CSP frame-ancestors.",
     "Add X-Frame-Options: DENY (or CSP frame-ancestors 'none')."),
    ("x-content-type-options", "LOW", "Missing X-Content-Type-Options",
     "Browser may MIME-sniff responses.",
     "Add X-Content-Type-Options: nosniff."),
    ("referrer-policy", "LOW", "Missing Referrer-Policy",
     "Full URLs (with tokens/params) may leak to third parties.",
     "Add Referrer-Policy: strict-origin-when-cross-origin."),
    ("permissions-policy", "LOW", "Missing Permissions-Policy",
     "No restriction on camera/mic/geolocation APIs.",
     "Add Permissions-Policy, e.g. camera=(), microphone=(), geolocation=()."),
]

def header_checks(pages, start, is_https):
    home = pages[0]
    h = home["_headers"]
    csp = h.get("content-security-policy", "")
    for name, sev, title, detail, fix in HEADER_RULES:
        if name == "strict-transport-security" and not is_https:
            continue
        if name == "x-frame-options":
            if "x-frame-options" not in h and "frame-ancestors" not in csp:
                add_finding(sev, "headers", title, home["final"], detail, fix)
            else:
                ok("Clickjacking protection present")
            continue
        if name not in h:
            add_finding(sev, "headers", title, home["final"], detail, fix)
        else:
            ok(f"{name}: {h[name][:80]}")
    if csp and ("'unsafe-inline'" in csp or "'unsafe-eval'" in csp):
        add_finding("LOW", "headers", "CSP allows unsafe-inline / unsafe-eval", home["final"],
                    "Weakens XSS protection significantly.",
                    "Move to nonces/hashes and drop unsafe-* sources.")
    for leak in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if h.get(leak):
            add_finding("LOW", "headers", f"Technology disclosure: {leak}", home["final"],
                        f"Value: {h[leak][:80]}",
                        "Strip version banners at server/reverse-proxy level.")

def cookie_checks(page):
    raw = page.get("_raw_headers")
    if not raw:
        return
    try:
        cookies = raw.get_all("Set-Cookie") or []
    except Exception:
        return
    is_https = page["final"].startswith("https")
    for c in cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        if is_https and "secure" not in low:
            add_finding("LOW", "cookies", f"Cookie '{name}' missing Secure flag", page["final"],
                        "", "Add the Secure attribute.")
        if "httponly" not in low:
            add_finding("LOW", "cookies", f"Cookie '{name}' missing HttpOnly", page["final"],
                        "", "Add HttpOnly so JS cannot read it (mitigates XSS theft).")
        if "samesite" not in low:
            add_finding("LOW", "cookies", f"Cookie '{name}' missing SameSite", page["final"],
                        "", "Add SameSite=Lax or Strict (CSRF hardening).")
    if cookies:
        ok(f"{len(cookies)} Set-Cookie header(s) audited")

def cors_check(url):
    probe = "https://rootscan-probe.invalid"
    r = fetch(url, headers={"Origin": probe})
    h = r["headers"]
    acao = h.get("access-control-allow-origin")
    acac = (h.get("access-control-allow-credentials") or "").lower() == "true"
    if not acao:
        ok("CORS: no cross-origin allowance")
        return
    if acao == "*":
        if acac:
            add_finding("HIGH", "cors", "CORS: wildcard origin WITH credentials", url,
                        f"ACAO: *  +  ACAC: true (browsers block this combo, but it signals misconfig).",
                        "Whitelist exact origins; never combine * with credentials.")
        else:
            add_finding("MEDIUM", "cors", "CORS: wildcard origin (*)", url,
                        "Any website can read responses of this endpoint.",
                        "Whitelist trusted origins instead of *.")
    elif acao == probe:
        sev = "HIGH" if acac else "MEDIUM"
        add_finding(sev, "cors", "CORS reflects arbitrary origins", url,
                    f"Sent Origin: {probe} — server echoed it back."
                    + (" WITH credentials!" if acac else ""),
                    "Validate Origin against a strict allowlist.")

def method_check(url):
    r = fetch(url, method="OPTIONS")
    allow = r["headers"].get("allow", "") + "," + r["headers"].get("access-control-allow-methods", "")
    allow = allow.upper()
    bad = [m for m in ("PUT", "DELETE", "TRACE", "TRACK", "CONNECT", "PATCH") if m in allow]
    if bad:
        add_finding("MEDIUM", "methods", f"Potentially dangerous HTTP methods: {', '.join(sorted(set(bad)))}", url,
                    "May allow uploading/deleting resources or cross-site tracing.",
                    "Disable unused methods (esp. TRACE/TRACK) at the web server.")
    else:
        ok(f"HTTP methods sane ({r['headers'].get('allow', 'n/a')})")

# ---------------------------------------------------------------- exposure

SENSITIVE = [
    ("/.git/HEAD",              r"^ref:\s+refs/",            "CRITICAL", "Exposed .git repository — source code leak",
     "Full source code (and possibly secrets in history) can be reconstructed.",
     "Block dotfile access in the web server; redeploy without .git."),
    ("/.git/config",            r"\[core\]",                 "HIGH", "Exposed .git config",
     "Repository metadata accessible.", "Block dotfile access in the web server."),
    ("/.env",                   r"(?m)^[A-Za-z_][A-Za-z0-9_]*=\S", "CRITICAL", "Environment file exposed (.env)",
     "Likely contains DB passwords & API keys, world-readable.",
     "Remove from webroot immediately and rotate ALL secrets inside."),
    ("/.svn/entries",           r"dir|has-props",            "HIGH", "Exposed .svn metadata",
     "Source tree structure readable.", "Block dotfile access."),
    ("/.htaccess",              r"(?i)(rewriteengine|deny from|allow from|authtype)", "LOW", ".htaccess readable",
     "Server config hints exposed.", "Deny access to .ht* files."),
    ("/server-status",          r"(?i)server status|scoreboard", "HIGH", "Apache server-status exposed",
     "Reveals requests, clients, vhosts.", "Restrict mod_status to localhost."),
    ("/server-info",            r"(?i)server information",   "HIGH", "Apache server-info exposed",
     "Full module/config disclosure.", "Restrict mod_info to localhost."),
    ("/phpinfo.php",            r"(?i)<title>phpinfo",       "MEDIUM", "phpinfo() page exposed",
     "Reveals paths, modules, env vars.", "Delete phpinfo pages from production."),
    ("/wp-json/wp/v2/users",    r'"slug"\s*:',               "HIGH", "WordPress user enumeration",
     "Author usernames exposed via REST API — aids brute force.",
     "Block /wp-json/wp/v2/users or harden via security plugin."),
    ("/wp-config.php.bak",      r"(?i)db_(name|user|password)", "CRITICAL", "WordPress config backup exposed",
     "DB credentials in cleartext.", "Delete the backup and rotate DB credentials."),
    ("/config.php.bak",         r"(?i)(password|db_|secret)", "HIGH", "Config backup exposed",
     "", "Delete backups from webroot."),
    ("/backup.sql",             r"(?i)(create table|insert into)", "HIGH", "SQL dump exposed (/backup.sql)",
     "", "Remove dumps from webroot; rotate data if leaked."),
    ("/database.sql",           r"(?i)(create table|insert into)", "HIGH", "SQL dump exposed (/database.sql)",
     "", "Remove dumps from webroot."),
    ("/dump.sql",               r"(?i)(create table|insert into)", "HIGH", "SQL dump exposed (/dump.sql)",
     "", "Remove dumps from webroot."),
    ("/backup.zip",             None,                        "MEDIUM", "Backup archive reachable (/backup.zip)",
     "", "Verify & remove; never store archives in webroot."),
    ("/composer.json",          r'"(require|name)"\s*:',     "LOW", "composer.json exposed",
     "Reveals package names & versions.", "Block access to composer files."),
    ("/package.json",           r'"(dependencies|scripts)"\s*:', "LOW", "package.json exposed",
     "Reveals package names & versions.", "Block access to package.json."),
    ("/.well-known/security.txt", r"(?i)contact\s*:",        "INFO", "security.txt present (GOOD)",
     "", "", ),
]

def soft404_profile(base, timeout):
    junk = "/rootscan-" + "".join(random.choices(string.ascii_lowercase, k=12))
    r = fetch(urllib.parse.urljoin(base, junk), timeout=timeout)
    return r["status"] in (200, 201, 204), junk

def exposure_checks(base, timeout, delay, verbose):
    soft, junk = soft404_profile(base, timeout)
    if soft:
        print(f"  {C.DIM}note: site returns 200 for missing pages (soft-404) — "
              f"exposure checks require content signatures{C.X}")
    for path, sig, sev, title, detail, fix in SENSITIVE:
        url = urllib.parse.urljoin(base, path)
        if delay:
            time.sleep(delay)
        r = fetch(url, timeout=timeout)
        if r["status"] != 200 or not r["body"]:
            continue
        body_txt = text_of(r)
        if sig:
            m = re.search(sig, body_txt)
            if not m:
                continue
            if title.endswith("(GOOD)"):
                ok(f"security.txt found ({path}) — nice practice 🌱")
                continue
            sample = body_txt[:160].replace("\n", " ⏎ ")
            add_finding(sev, "exposure", title, url,
                        (detail + " " if detail else "") + f"sample: {C.DIM}{sample}{C.X}", fix)
        else:
            if soft:
                if verbose:
                    print(f"  {C.DIM}(skip {path} — soft-404 ambiguity){C.X}")
                continue
            add_finding(sev, "exposure", title, url, detail, fix)

def robots_and_sitemap(base, timeout):
    seeds = []
    r = fetch(urllib.parse.urljoin(base, "/robots.txt"), timeout=timeout)
    if r["status"] == 200 and re.search(r"(?i)user-agent", text_of(r)):
        txt = text_of(r)
        dis = [l.split(":", 1)[1].strip() for l in txt.splitlines()
               if l.lower().startswith("disallow:") and l.split(":", 1)[1].strip()]
        sms = [l.split(":", 1)[1].strip() for l in txt.splitlines()
               if l.lower().startswith("sitemap:")]
        ok(f"robots.txt present — {len(dis)} disallow rule(s), {len(sms)} sitemap(s)")
        if dis:
            preview = ", ".join(dis[:10]) + (" …" if len(dis) > 10 else "")
            add_finding("INFO", "recon", f"robots.txt reveals {len(dis)} hidden path(s)",
                        urllib.parse.urljoin(base, "/robots.txt"),
                        f"Interesting: {preview}",
                        "Never rely on robots.txt to hide sensitive areas — it is public.")
        for sm in sms[:2]:
            seeds += parse_sitemap(sm, timeout)
    else:
        seeds += parse_sitemap(urllib.parse.urljoin(base, "/sitemap.xml"), timeout)
    return seeds

def parse_sitemap(url, timeout):
    r = fetch(url, timeout=timeout)
    if r["status"] != 200:
        return []
    locs = re.findall(r"<loc>\s*([^<]+)\s*</loc>", text_of(r))[:100]
    if locs:
        ok(f"sitemap parsed — {len(locs)} URL(s) fed into the crawler")
    return locs

# ---------------------------------------------------------------- app checks

CSRF_NAME = re.compile(r"(?i)(csrf|xsrf|token|authenticity|nonce|__request|_token)")
SENSITIVE_COMMENT = re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token|todo|fixme|hack|bug|credential)")

def app_checks(pages):
    forms_seen, mixed, comments_hit, generators = 0, [], [], set()
    for p in pages:
        pp = p.get("_parser")
        html = p.get("_html") or ""
        if not pp:
            continue
        if pp.meta_generator:
            generators.add(pp.meta_generator)
        for f in pp.forms:
            forms_seen += 1
            has_pw = any(i.get("type", "").lower() == "password" for i in f["inputs"])
            names = [i.get("name", "") for i in f["inputs"] if i.get("name")]
            if f["action"].startswith("http://") and p["final"].startswith("https"):
                add_finding("HIGH" if has_pw else "MEDIUM", "forms",
                            "Form on HTTPS page posts to plain HTTP", p["final"],
                            f"action={f['action']}",
                            "Post to HTTPS endpoints only.")
            if has_pw and f["method"] == "GET":
                add_finding("HIGH", "forms", "Password field submitted via GET", p["final"],
                            "Credentials land in URLs, logs and browser history.",
                            "Use POST with autocomplete attributes.")
            if names and not any(CSRF_NAME.search(n) for n in names):
                add_finding("LOW", "forms", "Form without obvious CSRF token", p["final"],
                            f"fields: {', '.join(names[:8])}",
                            "Add per-session CSRF tokens (or verify framework defaults).")
        if p["final"].startswith("https"):
            cnt = len(re.findall(r"(?:src|href)\s*=\s*[\"']http://", html, re.I))
            if cnt:
                mixed.append((p["final"], cnt))
        for c in pp.comments:
            if SENSITIVE_COMMENT.search(c):
                comments_hit.append((p["final"], c[:120]))
    if forms_seen:
        ok(f"{forms_seen} form(s) audited")
    if generators:
        add_finding("INFO", "fingerprint", f"Generator meta: {', '.join(sorted(generators))}",
                    pages[0]["final"], "", "Harmless, but helps attackers pick exploits.")
    for url, cnt in mixed[:5]:
        add_finding("LOW", "mixed", f"Mixed content ({cnt} http:// assets)", url,
                    "", "Load all sub-resources over HTTPS.")
    for url, c in comments_hit[:5]:
        add_finding("LOW", "comments", "Suspicious keyword in HTML comment", url,
                    f"{C.DIM}<!-- {c} -->{C.X}", "Strip comments from production output.")

def reflection_check(pages, opts):
    """Opt-in (--active): benign reflection canary for possible XSS."""
    tested = 0
    for p in pages:
        if tested >= 10:
            break
        parts = urllib.parse.urlsplit(p["final"])
        qs = urllib.parse.parse_qsl(parts.query)
        if not qs:
            continue
        marker = "rsc" + "".join(random.choices(string.digits, k=5)) + "'\"><rsc"
        for k, _v in qs[:2]:
            if tested >= 10:
                break
            new_q = urllib.parse.urlencode([(k, marker)] + [(a, b) for a, b in qs if a != k])
            probe = urllib.parse.urlunsplit(parts._replace(query=new_q))
            if opts.delay:
                time.sleep(opts.delay)
            r = fetch(probe, timeout=opts.timeout)
            tested += 1
            if marker in text_of(r):
                add_finding("MEDIUM", "reflected", f"Reflected input in parameter '{k}'", p["final"],
                            "Unique canary string echoed unescaped — investigate for XSS.",
                            "Contextually output-encode all reflected data; add CSP.")
    ok(f"reflection probes sent: {tested} (benign canary, no payloads)")

# ---------------------------------------------------------------- reports

def build_report(target, pages, started):
    score, grade = grade_and_score()
    counts = {s: sum(1 for f in FINDINGS if f["severity"] == s) for s in SEV_ORDER}
    return {
        "tool": "RootScan", "version": VERSION, "target": target,
        "date": datetime.datetime.now().isoformat(timespec="seconds"),
        "duration_s": round(time.monotonic() - started, 1),
        "score": score, "grade": grade, "counts": counts,
        "pages_crawled": len(pages),
        "pages": [{k: p[k] for k in ("url", "status", "content_type", "depth")} for p in pages],
        "findings": sorted(FINDINGS, key=lambda f: SEV_ORDER[f["severity"]]),
    }

def write_json(report, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    return path

HTML_CSS = """
*{box-sizing:border-box;margin:0;font-family:'Segoe UI',system-ui,sans-serif}
body{background:#0b1020;color:#e8ecf8;padding:32px}
.wrap{max-width:960px;margin:auto}
h1{font-size:26px}.sub{color:#93a0c9;margin:6px 0 24px}
.top{display:flex;gap:24px;align-items:center;background:#141b34;border:1px solid #26305c;
border-radius:16px;padding:24px;margin-bottom:24px}
.grade{width:110px;height:110px;border-radius:50%;display:flex;align-items:center;justify-content:center;
font-size:44px;font-weight:800;flex:none}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.chip{padding:6px 12px;border-radius:999px;font-size:12px;font-weight:700}
.CRITICAL{background:#3b0f3f;color:#f0abfc}.HIGH{background:#3b1010;color:#fca5a5}
.MEDIUM{background:#3b2a0f;color:#fcd34d}.LOW{background:#0f1f3b;color:#93c5fd}
.INFO{background:#1a2340;color:#aab6e0}
.f{background:#141b34;border:1px solid #26305c;border-left:4px solid #888;border-radius:12px;
padding:16px 18px;margin-bottom:12px}
.f h3{font-size:15px}.f .u{color:#93a0c9;font-size:12px;margin:4px 0}
.f .d{font-size:13px;color:#c9d2ef}.f .x{font-size:12px;color:#7ee2a8;margin-top:6px}
.f.CRITICAL{border-left-color:#d946ef}.f.HIGH{border-left-color:#ef4444}
.f.MEDIUM{border-left-color:#f59e0b}.f.LOW{border-left-color:#3b82f6}.f.INFO{border-left-color:#64748b}
details{background:#141b34;border:1px solid #26305c;border-radius:12px;padding:14px 18px;margin-top:8px}
summary{cursor:pointer;font-weight:700}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:12px}
td,th{padding:6px 8px;border-bottom:1px solid #26305c;text-align:left}
footer{color:#64748b;font-size:11px;margin-top:28px;text-align:center}
"""

def write_html(report, path):
    g = report["grade"]
    gcol = {"A": "#22c55e", "B": "#84cc16", "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"}[g]
    chips = "".join(f'<span class="chip {s}">{s}: {n}</span>'
                    for s, n in report["counts"].items() if n or s in ("HIGH", "MEDIUM"))
    rows = []
    for f in report["findings"]:
        rows.append(
            f'<div class="f {f["severity"]}"><h3>[{f["severity"]}] '
            f'{html_esc(f["title"])}</h3><div class="u">{html_esc(f["url"])}</div>'
            f'<div class="d">{html_esc(f.get("detail") or "")}</div>'
            + (f'<div class="x">↳ {html_esc(f["fix"])}</div>' if f.get("fix") else "")
            + "</div>")
    pages_rows = "".join(
        f"<tr><td>{p['status']}</td><td>d{p['depth']}</td>"
        f"<td>{html_esc(p['url'])}</td><td>{html_esc(p['content_type'])}</td></tr>"
        for p in report["pages"])
    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>RootScan report — {html_esc(report['target'])}</title><style>{HTML_CSS}</style></head>
<body><div class="wrap">
<h1>🌱 RootScan Security Report</h1>
<div class="sub">{html_esc(report['target'])} · {html_esc(report['date'])} ·
{report['duration_s']}s · {report['pages_crawled']} pages crawled</div>
<div class="top">
  <div class="grade" style="background:#0b1020;border:4px solid {gcol};color:{gcol}">{g}</div>
  <div><div style="font-size:22px;font-weight:800">Security score: {report['score']}/100</div>
  <div class="stats">{chips}</div></div>
</div>
<h2 style="margin-bottom:12px">Findings ({len(report['findings'])})</h2>
{''.join(rows) or '<p style="color:#7ee2a8">🎉 No findings. Clean as a freshly plowed field.</p>'}
<details><summary>Crawl map ({report['pages_crawled']} pages)</summary>
<table><tr><th>HTTP</th><th>depth</th><th>URL</th><th>type</th></tr>{pages_rows}</table></details>
<footer>Generated by RootScan v{VERSION} — authorized security testing only. Not a silver bullet.</footer>
</div></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path

def html_esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))

# ---------------------------------------------------------------- main

def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="rootscan",
        description="RootScan — deep, respectful full-stack web security scanner. "
                    "AUTHORIZED USE ONLY.",
        epilog="examples:\n"
               "  python3 rootscan.py https://example.com\n"
               "  python3 rootscan.py https://example.com -d 3 -m 120 --html report.html\n"
               "  python3 rootscan.py https://example.com --no-crawl     # quick headers/TLS only\n"
               "  python3 rootscan.py https://example.com --active       # + benign reflection probes\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", help="target URL (https://example.com)")
    ap.add_argument("-d", "--depth", type=int, default=2, help="crawl depth (default: 2)")
    ap.add_argument("-m", "--max-pages", type=int, default=40, help="max pages to crawl (default: 40)")
    ap.add_argument("--delay", type=float, default=0.2, help="delay between requests, seconds (default: 0.2)")
    ap.add_argument("--timeout", type=float, default=10, help="request timeout, seconds (default: 10)")
    ap.add_argument("--max-time", type=int, default=180, help="overall scan budget, seconds (default: 180)")
    ap.add_argument("--no-crawl", action="store_true", help="skip crawling; scan homepage only")
    ap.add_argument("--active", action="store_true", help="enable benign active probes (reflection canary)")
    ap.add_argument("--json", metavar="PATH", help="write JSON report")
    ap.add_argument("--html", metavar="PATH", help="write HTML report")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="version", version=f"RootScan {VERSION}")
    return ap.parse_args(argv)

def main(argv=None):
    opts = parse_args(argv or sys.argv[1:])
    url = opts.url.strip()
    if not re.match(r"^https?://", url):
        url = "https://" + url
    banner()
    started = time.monotonic()

    print(f"{C.BOLD}[*] Target{C.X}  : {url}")
    print(f"{C.BOLD}[*] Config{C.X}  : depth={opts.depth} max_pages={opts.max_pages} "
          f"delay={opts.delay}s active={opts.active}")

    base_probe = fetch(url, timeout=opts.timeout)
    if base_probe["err"] and url.startswith("https://"):
        alt = "http://" + url[len("https://"):]
        retry = fetch(alt, timeout=opts.timeout)
        if not retry["err"]:
            url, base_probe = alt, retry
    if base_probe["err"]:
        print(f"{C.R}[!] Cannot reach target: {base_probe['err']}{C.X}")
        return 2
    base = base_probe["final"]

    # 1 ── transport
    section("TLS & TRANSPORT")
    tls_check(base)
    is_https = base.startswith("https")

    # 2 ── recon seeds
    section("RECON (robots & sitemap)")
    seeds = robots_and_sitemap(base, opts.timeout)

    # 3 ── crawl
    section("CRAWL")
    if opts.no_crawl:
        pp = PageParser(base)
        try:
            pp.feed(text_of(base_probe))
        except Exception:
            pass
        pages = [{"url": base, "final": base, "status": base_probe["status"],
                  "content_type": base_probe["headers"].get("content-type", "").split(";")[0],
                  "depth": 0, "_parser": pp, "_html": text_of(base_probe),
                  "_headers": base_probe["headers"], "_raw_headers": base_probe["raw"]}]
        print(f"  {C.DIM}(--no-crawl: homepage only){C.X}")
    else:
        pages = crawl(base, opts)
        if seeds and len(pages) < opts.max_pages:
            extra = [s for s in seeds if urllib.parse.urlsplit(s).hostname ==
                     urllib.parse.urlsplit(base).hostname][: max(0, opts.max_pages - len(pages))]
            for s in extra[: min(len(extra), 25)]:
                if opts.delay:
                    time.sleep(opts.delay)
                r = fetch(s, timeout=opts.timeout)
                if not r["err"]:
                    pp = PageParser(r["final"])
                    try:
                        pp.feed(text_of(r))
                    except Exception:
                        pass
                    pages.append({"url": s, "final": r["final"], "status": r["status"],
                                  "content_type": r["headers"].get("content-type", "").split(";")[0],
                                  "depth": 99, "_parser": pp, "_html": text_of(r),
                                  "_headers": r["headers"], "_raw_headers": r["raw"]})
                    print(f"  {C.DIM}[{r['status']}] (sitemap) {s}{C.X}")
    ok(f"crawl map: {len(pages)} page(s)")

    # 4 ── checks
    section("SECURITY HEADERS")
    header_checks(pages, base, is_https)

    section("COOKIES")
    cookie_checks(pages[0])

    section("CORS & HTTP METHODS")
    cors_check(base)
    method_check(base)

    section("SENSITIVE EXPOSURE (root-level)")
    exposure_checks(base, opts.timeout, min(opts.delay, 0.35), opts.verbose)

    section("APPLICATION (forms / comments / mixed content)")
    app_checks(pages)

    if opts.active:
        section("ACTIVE PROBES (benign reflection canary)")
        reflection_check(pages, opts)

    # 5 ── results
    section("FINDINGS")
    ordered = sorted(FINDINGS, key=lambda f: SEV_ORDER[f["severity"]])
    if not ordered:
        print(f"  {C.G}🎉 No findings — clean as a freshly plowed field.{C.X}")
    for f in ordered:
        finding_line(f)

    score, grade = grade_and_score()
    counts = {s: sum(1 for f in FINDINGS if f["severity"] == s) for s in SEV_ORDER}
    section("SCORE")
    gcol = {"A": C.G, "B": C.G, "C": C.Y, "D": C.Y, "F": C.R}[grade]
    print(f"  Grade: {gcol}{C.BOLD}{grade}{C.X}   Score: {C.BOLD}{score}/100{C.X}   "
          f"({C.M}{counts['CRITICAL']} crit{C.X} · {C.R}{counts['HIGH']} high{C.X} · "
          f"{C.Y}{counts['MEDIUM']} med{C.X} · {C.B}{counts['LOW']} low{C.X} · "
          f"{C.DIM}{counts['INFO']} info{C.X})")

    report = build_report(base, pages, started)
    if opts.json:
        print(f"\n  {C.G}📄 JSON report → {write_json(report, opts.json)}{C.X}")
    if opts.html:
        print(f"  {C.G}📄 HTML report → {write_html(report, opts.html)}{C.X}")

    print(f"\n{C.DIM}Done in {time.monotonic() - started:.1f}s — "
          f"remember: authorized testing only. 🌱{C.X}")
    return 1 if counts["CRITICAL"] or counts["HIGH"] else 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.Y}Interrupted by user.{C.X}")
        sys.exit(130)
