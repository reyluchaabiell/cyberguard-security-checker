# CyberGuard — Website Security Assessment Tool

> A free, browser-based website security checker that helps developers, website administrators, UMKM (small business owners), and IT students understand the basic security posture of their websites.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Project Goals](#2-project-goals)
3. [Key Features](#3-key-features)
4. [Technology Stack](#4-technology-stack)
5. [Project Directory Structure](#5-project-directory-structure)
6. [How It Works](#6-how-it-works)
7. [DNS-over-HTTPS API](#7-dns-over-https-api)
8. [Security Scoring Methodology](#8-security-scoring-methodology)
9. [Browser Security Limitations](#9-browser-security-limitations)
10. [How to Run Locally](#10-how-to-run-locally)
11. [GitHub Pages Deployment](#11-github-pages-deployment)
12. [Known Limitations](#12-known-limitations)
13. [Future Development Roadmap](#13-future-development-roadmap)
14. [Responsible Use Disclaimer](#14-responsible-use-disclaimer)

---

## 1. Project Overview

**CyberGuard** is a static, frontend-only website security assessment tool that runs entirely in the browser. It performs real DNS lookups using Google's public DNS-over-HTTPS API and analyses HTTP security headers provided by the user to produce an educational security report for any domain.

The application translates technical security findings into plain-language explanations suitable for non-technical users, while also providing detailed remediation instructions for experienced developers.

**No account. No backend. No data retention. Pure browser.**

---

## 2. Project Goals

| Goal | Description |
|---|---|
| **Accuracy** | All findings are based on real DNS responses or user-provided headers — never fabricated. |
| **Transparency** | Checks that cannot be performed are clearly labeled "Unable to Verify" or "UNKNOWN". |
| **Education** | Every finding includes a plain-language explanation, risk description, and actionable remediation. |
| **Privacy** | No user data is stored. Only DNS queries reach external servers (Google DoH). |
| **Accessibility** | Semantic HTML, keyboard navigation, ARIA labels, and accessible colour contrast. |
| **Simplicity** | No build tools, no frameworks, no package managers — four files, deployable anywhere. |

---

## 3. Key Features

### Module 1 — Domain Input & Scan Controls
- Domain normalisation (strips protocol, trailing slashes, paths, ports)
- Strict domain validation (RFC-compliant label checking)
- Blocks dangerous URL schemes (`javascript:`, `data:`, `file:`)
- Optional DKIM selector input
- Optional HTTP response headers paste area
- Scan, Quick Demo, and Reset buttons
- Real-time progress indicator

### Module 2 — DNS & Email Security Audit
- **A, AAAA, MX, NS, TXT** record retrieval via Google DoH
- **SPF** — detects presence, multiple records, and weak policies (`+all`, `?all`)
- **DMARC** — parses `p=` policy value, explains none/quarantine/reject
- **DKIM** — tests multiple common selectors, explains selector variability

### Module 3 — HTTPS & Security Headers Audit
Six headers evaluated:
- Strict-Transport-Security (HSTS) — `max-age`, `includeSubDomains`
- Content-Security-Policy (CSP) — detects `unsafe-inline`, `unsafe-eval`, wildcards
- X-Frame-Options — validates `DENY`/`SAMEORIGIN`, warns about deprecated `ALLOW-FROM`
- X-Content-Type-Options — validates `nosniff`
- Referrer-Policy — classifies weak vs strong policies
- Permissions-Policy — presence check

Two inspection methods:
- **User-provided headers** (paste output of `curl -I https://example.com`) — high confidence
- **Browser fetch** — CORS-limited, correctly shows UNKNOWN when unavailable

### Module 4 — HTTPS & TLS Assessment
- Tests HTTPS connectivity via browser Fetch API (no-cors mode)
- Honestly labels unsupported TLS checks (certificate chain, cipher suites, revocation) as "Not Available in Browser-Only Mode"

### Module 5 — Security Dashboard
- Animated circular score gauge
- Summary counts: Passed / Warnings / Failed / Unknown
- Color-coded check cards (green/amber/red/blue/gray)
- Score explanation with denominator details

### Module 6 — Deterministic Risk Scoring Engine
- JavaScript-only scoring — no AI, no randomness
- UNKNOWN checks excluded from denominator
- Warnings receive 50% credit
- Scoring weights defined in a central CONFIG object

### Module 7 — Educational Findings & Remediation
- Accordion-style detail cards for every check
- Sections: What Was Found / Why It Matters / Risk / Fix / Example Configuration
- Copy Configuration buttons for every code example
- Source and confidence tags per finding

---

## 4. Technology Stack

| Component | Technology |
|---|---|
| Markup | HTML5 (semantic) |
| Styling | Tailwind CSS (CDN) + custom CSS |
| Logic | Vanilla JavaScript ES6+ |
| DNS Lookups | Google DNS-over-HTTPS JSON API |
| Fonts | Google Fonts (Inter, JetBrains Mono) |
| Backend | None |
| Build Tools | None |
| Package Manager | None |
| Deployment | GitHub Pages (static) |

---

## 5. Project Directory Structure

```
cyberguard/
├── index.html   ← Application shell, semantic HTML structure
├── style.css    ← Custom styles complementing Tailwind utilities
├── script.js    ← All application logic (modular vanilla JS)
└── README.md    ← This file
```

### JavaScript Internal Architecture

```
script.js
│
├── CONFIG
│   ├── API_ENDPOINTS
│   └── SECURITY_WEIGHTS
│
├── DOMAIN_VALIDATOR
│   ├── normalizeDomain()
│   └── validateDomain()
│
├── DNS_ENGINE
│   ├── queryDNS()
│   ├── fetchRecords()
│   ├── checkDNSRecords()
│   ├── checkSPF()
│   ├── checkDMARC()
│   └── checkDKIM()
│
├── HEADER_ENGINE
│   ├── parseHeaders()
│   ├── analyzeHSTS()
│   ├── analyzeCSP()
│   ├── analyzeXFrameOptions()
│   ├── analyzeContentTypeOptions()
│   ├── analyzeReferrerPolicy()
│   └── analyzePermissionsPolicy()
│
├── HTTPS_ENGINE
│   └── checkHTTPSAvailability()
│
├── RISK_ENGINE
│   ├── calculateRiskScore()
│   └── determineRiskLevel()
│
├── REPORT_ENGINE
│   └── getFindings()
│
└── UI_ENGINE
    ├── renderProgress()
    ├── renderScore()
    ├── renderChecksGrid()
    ├── renderFindings()
    ├── renderDNSRecords()
    ├── renderTLSInfo()
    └── resetApplication()
```

---

## 6. How It Works

### Step 1 — Domain Input
The user enters a domain name (e.g., `example.com`). CyberGuard:
1. Normalises the input (strips `https://`, paths, ports)
2. Validates the domain against RFC label rules
3. Rejects dangerous schemes (`javascript:`, `data:`, `file:`)

### Step 2 — DNS Queries (Parallel)
CyberGuard fires parallel DNS-over-HTTPS requests for:
- A records (IPv4)
- AAAA records (IPv6)
- MX records (mail servers)
- NS records (nameservers)
- TXT records (SPF, verification tokens)
- TXT at `_dmarc.<domain>` (DMARC policy)
- TXT at `<selector>._domainkey.<domain>` (DKIM public key)

Uses `Promise.allSettled()` so a single DNS failure never blocks other checks.

### Step 3 — Header Analysis
If the user pastes HTTP response headers, CyberGuard parses them and evaluates all six security headers. If no headers are pasted, header checks are marked UNKNOWN (correctly — the browser cannot read cross-origin response headers due to CORS).

### Step 4 — HTTPS Check
A `HEAD` request with `mode: no-cors` is attempted to `https://<domain>`. An opaque response indicates HTTPS is reachable. Network errors indicate a failure.

### Step 5 — Score Calculation
Only verified checks (not UNKNOWN) are included in the denominator. Warnings earn 50% credit.

### Step 6 — Results
The dashboard shows:
- Animated score gauge
- Color-coded check cards
- Expandable finding cards with educational content
- Raw DNS records
- HTTPS/TLS status

---

## 7. DNS-over-HTTPS API

CyberGuard uses Google's public **DNS-over-HTTPS (DoH)** JSON API:

```
https://dns.google/resolve?name=<name>&type=<type>
```

**Documentation:** https://developers.google.com/speed/public-dns/docs/doh/json

### Why DoH?
- Standard DNS lookups are not available from browser JavaScript.
- DoH uses HTTPS, so it works from any browser with internet access.
- Google's DoH API is public, free, and does not require an API key.
- Responses include the DNS status code, allowing correct handling of NXDOMAIN vs errors.

### Example Request
```
https://dns.google/resolve?name=_dmarc.example.com&type=TXT
```

### Example Response
```json
{
  "Status": 0,
  "Answer": [
    {
      "name": "_dmarc.example.com.",
      "type": 16,
      "TTL": 300,
      "data": "\"v=DMARC1; p=reject; rua=mailto:dmarc@example.com\""
    }
  ]
}
```

### Status Codes Used
| Status | Meaning |
|---|---|
| 0 | No error |
| 3 | NXDOMAIN — name does not exist |
| -1 (internal) | Network error or timeout |

---

## 8. Security Scoring Methodology

### Weights Table

| Security Control | Weight | Rationale |
|---|---:|---|
| HTTPS Availability | 20 | Foundation of all web security |
| CSP | 15 | Primary XSS defense |
| DMARC | 15 | Email spoofing enforcement |
| HSTS | 10 | Prevents protocol downgrade attacks |
| SPF | 10 | Email sender authentication |
| DKIM | 10 | Email integrity verification |
| X-Frame-Options | 5 | Clickjacking prevention |
| X-Content-Type-Options | 5 | MIME sniffing prevention |
| Referrer-Policy | 5 | Information disclosure reduction |
| Permissions-Policy | 5 | Browser feature restriction |
| **Total** | **100** | |

### Scoring Rules

| Check Result | Score Credit |
|---|---|
| PASS | 100% of weight |
| WARN | 50% of weight |
| FAIL | 0% of weight |
| UNKNOWN | Excluded from denominator |
| INFO | Excluded from denominator |

### Formula

```
Score = (Σ earned weights / Σ applicable weights) × 100
```

Where "applicable weights" excludes all UNKNOWN and INFO checks.

### Risk Levels

| Score Range | Risk Level |
|---|---|
| 90–100 | Low Risk |
| 70–89 | Medium Risk |
| 40–69 | High Risk |
| 0–39 | Critical Risk |

> **Important:** The score is an educational indicator of tested controls. It is **not** a formal security certification, penetration test result, or guarantee of security.

---

## 9. Browser Security Limitations

CyberGuard is a static, browser-only application. The following limitations are inherent to this architecture and are **correctly handled** in the codebase:

| Limitation | Reason | How CyberGuard Handles It |
|---|---|---|
| Cross-origin headers | CORS policy blocks response header access | Marked UNKNOWN — user can paste headers manually |
| TLS certificate chain | No browser API exposes certificate details | Labeled "Not Available in Browser-Only Mode" |
| TLS cipher suites | Negotiation details not exposed to JS | Labeled "Not Available in Browser-Only Mode" |
| Certificate expiry/revocation | Not accessible via browser APIs | Labeled "Not Available in Browser-Only Mode" |
| HTTP→HTTPS redirect detection | Cannot make plain HTTP request from HTTPS page | Labeled UNKNOWN |
| Rate limiting | No server-side control | Acknowledged in code — cannot be enforced |

### Recommended External Tools for Full TLS Inspection
- https://www.ssllabs.com/ssltest/
- https://testssl.sh (command-line)
- https://securityheaders.com (HTTP headers)
- https://dmarcian.com (email authentication)

---

## 10. How to Run Locally

No build step required.

### Option A: Python HTTP Server (recommended)
```bash
cd cyberguard
python3 -m http.server 8080
# Open http://localhost:8080
```

### Option B: Node.js (if installed)
```bash
cd cyberguard
npx serve .
# or
npx http-server . -p 8080
```

### Option C: VS Code Live Server
1. Install the **Live Server** extension in VS Code.
2. Open `index.html`.
3. Click **Go Live** in the status bar.

### Option D: Direct File Open
Open `index.html` directly in your browser.
> ⚠ The Google DoH API requires an internet connection. DNS queries will fail offline.
> ⚠ Some browsers block mixed-content or restrict fetch from `file://` URLs.
> Using a local HTTP server is strongly recommended.

---

## 11. GitHub Pages Deployment

1. **Push all four files to a GitHub repository:**
   ```bash
   git init
   git add index.html style.css script.js README.md
   git commit -m "Initial commit — CyberGuard v1.0.0"
   git remote add origin https://github.com/<your-username>/<your-repo>.git
   git push -u origin main
   ```

2. **Enable GitHub Pages:**
   - Go to your repository on GitHub.
   - Click **Settings** → **Pages**.
   - Under "Source", select **Deploy from a branch**.
   - Select **main** branch and **/ (root)** folder.
   - Click **Save**.

3. **Access your site:**
   Your site will be live at:
   ```
   https://<your-username>.github.io/<your-repo>/
   ```

4. **Custom domain (optional):**
   Add a `CNAME` file containing your custom domain and configure your DNS accordingly.

---

## 12. Known Limitations

| Limitation | Detail |
|---|---|
| **No TLS inspection** | Certificate validity, cipher suites, and protocol versions require a backend. Use SSL Labs externally. |
| **CORS prevents automatic header checks** | HTTP security headers can only be evaluated if the user pastes them manually. |
| **DKIM selector guessing** | CyberGuard tests 5 common selectors. If your provider uses a different selector, the check will show WARN even if DKIM is correctly configured. |
| **No authentication check** | Cannot verify whether login forms enforce MFA or account lockout policies. |
| **No vulnerability scanning** | Does not check for known CVEs, outdated software, or exposed admin panels. |
| **Google DoH rate limits** | CyberGuard makes multiple DNS queries per scan. Very frequent scanning may encounter Google's rate limits. |
| **Internet required** | All DNS queries reach Google's servers. Offline use is not supported for DNS checks. |
| **Static hosting only** | Cannot perform server-side checks, store scan history, or offer authenticated features. |

---

## 13. Future Development Roadmap

| Priority | Feature |
|---|---|
| High | Optional backend service (Node.js/Python) for real HTTPS header fetch, TLS inspection |
| High | DNSSEC validation check |
| Medium | CAA record check (Certificate Authority Authorization) |
| Medium | Scan history export (JSON / PDF report) |
| Medium | Email notification for recurring scans |
| Medium | BIMI record support |
| Low | Dark/light mode toggle |
| Low | Multiple domain comparison view |
| Low | API endpoint for programmatic access |
| Low | Integration with Shodan/Censys for exposed service detection |

---

## 14. Responsible Use Disclaimer

CyberGuard is designed for **legitimate, authorised security assessment purposes only**.

**You MUST only scan domains that you own or have explicit written authorisation to test.**

Scanning domains without permission may violate:
- Computer Fraud and Abuse Act (CFAA) — United States
- Computer Misuse Act — United Kingdom
- UU ITE (Undang-Undang Informasi dan Transaksi Elektronik) — Indonesia
- GDPR and similar data protection regulations in the European Union
- Applicable local laws in your jurisdiction

**CyberGuard**:
- Does not store any domain names or scan results.
- Does not send data to any server other than Google's public DoH API.
- Cannot be used to exploit vulnerabilities — it only reads publicly available DNS records and evaluates headers you provide.
- Provides educational assessments only — findings are not equivalent to a professional penetration test.

The developers of CyberGuard accept no liability for misuse of this tool.

---

*CyberGuard v1.0.0 — Built with HTML5, Tailwind CSS, and Vanilla JavaScript.*  
*Scan results are for educational purposes only and do not constitute a formal security audit or certification.*
