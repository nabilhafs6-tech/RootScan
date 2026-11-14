# 🌱 RootScan

**Deep, respectful, full-stack web security scanner — straight from your terminal.**
Crawls to the roots of a target site, then audits TLS, security headers, root-level file
exposure, CORS, HTTP methods, cookies, forms, mixed content and more — ending with a
0–100 security score, an A–F grade, and a slick HTML report.

> ⚠️ **Authorized use only.** RootScan is a *defensive* tool for auditing assets you own
> or have explicit written permission to test. Unauthorized scanning may be illegal.
> You are responsible for your own usage.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

## ✨ Features

| Area | What it checks |
|---|---|
| 🕸 **Deep crawler** | BFS same-origin crawl (configurable depth/page budget), feeds on `robots.txt` + `sitemap.xml`, parses links & forms |
| 🔒 **TLS / transport** | Cert validity & expiry countdown, obsolete protocol detection, plain-HTTP detection |
| 🛡 **Security headers** | CSP, HSTS, X-Frame-Options / frame-ancestors, nosniff, Referrer-Policy, Permissions-Policy, unsafe-inline analysis, version-banner disclosure |
| 🍪 **Cookies** | Missing `Secure` / `HttpOnly` / `SameSite` flags, per cookie |
| 🌍 **CORS** | Wildcard `*`, reflective origin echoing, credential combos |
| 🔧 **HTTP methods** | `OPTIONS` audit — flags PUT/DELETE/TRACE/TRACK/PATCH if enabled |
| 🗂 **Root exposure** | `/.git/HEAD`, `/.env`, `.svn`, SQL dumps, `phpinfo()`, `server-status`, WP user enumeration, config backups, `composer.json`, soft-404 aware (signature-verified, low false positives) |
| 📝 **App surface** | Form audit (password-over-GET, HTTPS→HTTP posts, CSRF-token heuristic), suspicious HTML comments, mixed content, generator fingerprint |
| 💉 **Active mode (opt-in)** | Benign reflection canary (`--active`) to surface possible XSS sinks — no payloads, ever |
| 📊 **Scoring & reports** | 0–100 score, A–F grade, colored terminal UI, `--json` / `--html` self-contained reports |

**Zero dependencies.** Pure Python 3.8+ standard library — clone it, run it, done.

## 🚀 Quick start

```bash
git clone https://github.com/nabilhafs6-tech/RootScan.git
cd RootScan
python3 rootscan.py https://example.com
```

Deeper scan + HTML report:

```bash
python3 rootscan.py https://example.com -d 3 -m 120 --html report.html --json report.json
```

Quick headers/TLS-only pass:

```bash
python3 rootscan.py https://example.com --no-crawl
```

Enable benign active probes:

```bash
python3 rootscan.py https://example.com --active
```

## ⚙️ Options

```
positional:
  url                  target URL (https://example.com)

-d, --depth N          crawl depth (default: 2)
-m, --max-pages N      max pages to crawl (default: 40)
--delay SEC            delay between requests (default: 0.2) — be nice to servers
--timeout SEC          request timeout (default: 10)
--max-time SEC         overall scan budget (default: 180)
--no-crawl             homepage-only scan
--active               enable benign reflection-canary probes
--json PATH            write JSON report
--html PATH            write HTML report
-v, --verbose          verbose output
```

**Exit codes:** `0` = no HIGH/CRITICAL findings · `1` = HIGH/CRITICAL found (CI-friendly) · `2` = target unreachable.

## 📄 Sample output

```
─── SCORE ──────────────────────────────────
  Grade: C   Score: 69/100   (0 crit · 1 high · 4 med · 5 low · 2 info)

  📄 HTML report → report.html
```

## 🧠 Notes

- **False-positive control:** sites that return `200` for *everything* (soft-404) are detected
  first; exposure findings then require matching content signatures.
- **Respectful by default:** rate-limited, capped page budget, identified User-Agent.
  Tune with `--delay` / `--max-pages` / `--max-time`.
- RootScan is a *scanner, not an oracle*: it surfaces common misconfigurations fast,
  but a clean report ≠ a secure app. Pair it with manual review.

## ⚖️ Legal / Ethics

Use RootScan **only** on systems you own or are explicitly authorized to test.
The authors accept no liability for misuse. See [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
for professional methodology.

## 📄 License

MIT © 2026 RootScan contributors.
