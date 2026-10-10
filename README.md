# Abliteration V3.3 🛡️

**Abliteration** is an enterprise-grade, lightweight Dynamic Application Security Testing (DAST) engine, cryptographic inspector, DNS/DMARC email security auditor, and OAST disposable email platform designed for developers, security engineers, and automated DevSecOps pipelines.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-green.svg)](https://python.org)
[![Security: Enterprise DAST](https://img.shields.io/badge/Security-Enterprise%20DAST-red.svg)](https://github.com/itzluthfi/abliteration)

---

## 🌟 Key Enterprise Features

### 1. 🕷️ Smart Web Spider / Crawler
- Recursively discovers internal links (`<a href>`), parses HTML forms (`<form>`), and maps parameters.
- Discovers hidden endpoints across single-page apps (SPA) and multi-page architectures.

### 2. 🛡️ WAF & Perimeter Detection
- Automatic fingerprinting of Web Application Firewalls (WAF) and CDNs (Cloudflare, AWS CloudFront, Akamai, Fastly, Imperva, Sucuri).

### 3. 📧 DNS & Email Spoofing Defense (SPF & DMARC)
- Audits domain DNS TXT records via DNS-over-HTTPS (DoH).
- Detects missing or permissive (`p=none`) DMARC and SPF policies that leave domains vulnerable to CEO fraud and email phishing.

### 4. 🔒 SSL/TLS Cryptographic Inspector
- Deep inspection of peer certificates via Python native `ssl` engine:
  - Days remaining until expiration (warns at <15 days, critical if expired).
  - Certificate Authority / Issuer transparency (Let's Encrypt, Cloudflare, DigiCert, etc.).
  - Protocol version audit (detects and warns on deprecated TLS 1.0, 1.1, and SSLv3).

### 5. 🍪 Cookie Security Hygiene Auditor
- Evaluates all `Set-Cookie` directives:
  - `HttpOnly`: Prevents cookie theft via Cross-Site Scripting (XSS).
  - `Secure`: Ensures cookies are never leaked over unencrypted Wi-Fi.
  - `SameSite`: Verifies `Strict` or `Lax` policy to defeat Cross-Site Request Forgery (CSRF).

### 6. 🎯 API & Hidden Attack Surface Discovery
- Probes for exposed internal documentation:
  - `/swagger.json`, `/openapi.json`, `/api-docs`, `/v2/api-docs`, `/swagger-ui.html`.
  - Active GraphQL endpoints (`/graphql`) with schema verification.

### 7. ⚡ OAST Disposable Email Engine (`--temp-mail`)
- Instant temporary inbox generator with real-time incoming email polling and automatic OTP code extraction for registration and account flow testing.

### 8. 🔍 Verifiable Proof-of-Concept (PoC) & Evidence
- Every single finding includes a 1-click reproducible `curl` command and raw response evidence snippet to prevent fictitious claims.

### 9. 🏆 Standard Security Scoring & CI/CD Quality Gate
- Computes a global Security Score (0–100) and Letter Grade (`A+` to `F`).
- Includes `--fail-on [HIGH|MEDIUM|LOW]` flag and pre-built GitHub Actions workflow.

---

## 🚀 Installation & Usage

```bash
git clone https://github.com/itzluthfi/abliteration.git
cd abliteration
pip install -r requirements.txt

# 1. Full Security Audit:
python abliteration.py -u https://your-site.com --max-pages 20

# 2. CI/CD Quality Gate (Fail pipeline if HIGH risk is detected):
python abliteration.py -u https://your-site.com --fail-on HIGH

# 3. Disposable Email Engine (OAST / Registration Testing):
python abliteration.py --temp-mail --listen-sec 120
```

---

## 📁 Architecture
```text
abliteration/
├── src/
│   ├── crawler.py          # Smart Web Spider & parameter extractor
│   ├── ssl_inspector.py    # Cryptographic & SSL/TLS certificate auditor
│   ├── auditor.py          # DAST checks, cookie hygiene, & scoring engine
│   ├── reporter.py         # Terminal, JSON, & interactive HTML report generator
│   └── tools/
│       ├── dns_auditor.py  # SPF, DMARC, RFC 9116 security.txt, & WAF detector
│       └── tempmail.py     # OAST disposable inbox client & OTP extractor
├── tests/
│   └── mock_lab.py         # Local vulnerable test lab server
├── .github/
│   └── workflows/
│       └── security-audit.yml  # Automated CI/CD pipeline
├── OUTPUT/
│   ├── audit_report.html   # Visual executive HTML report
│   └── audit_report.json   # Machine-readable JSON report
├── requirements.txt
├── abliteration.py         # Main CLI entry point
└── README.md
```

---

## ⚖️ Disclaimer
This tool is built strictly for authorized security auditing, defensive security engineering, educational research, and internal website validation. Never audit systems without explicit written permission from the owner.

## 👤 Author
- **itzluthfi**
