# Abliteration V3.1 🛡️

**Abliteration** is an enterprise-grade, lightweight Dynamic Application Security Testing (DAST) engine, cryptographic inspector, and web security auditor designed for developers, security engineers, and automated DevSecOps pipelines.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-green.svg)](https://python.org)
[![Security: DAST](https://img.shields.io/badge/Security-Enterprise%20DAST-red.svg)](https://github.com/itzluthfi/abliteration)

---

## 🌟 Enterprise Features

Unlike simple single-URL toy scripts, **Abliteration v3.1** incorporates features comparable to commercial enterprise scanners:

### 1. 🕷️ Smart Web Spider / Crawler
- Recursively traverses internal links (`<a href>`), parses HTML forms (`<form>`), and extracts real query parameters.
- Discovers hidden endpoints across single-page apps (SPA) and multi-page architectures.

### 2. 🔒 SSL/TLS Cryptographic Inspector
- Deep inspection of peer certificates via Python native `ssl` engine:
  - Days remaining until expiration (warns at <15 days, critical if expired).
  - Certificate Authority / Issuer transparency (Let's Encrypt, Cloudflare, DigiCert, etc.).
  - Protocol version audit (detects and warns on deprecated TLS 1.0, 1.1, and SSLv3).
  - Weak cryptographic cipher and key-length detection.

### 3. 🍪 Cookie Security Hygiene Auditor
- Evaluates all `Set-Cookie` directives against modern defense standards:
  - `HttpOnly`: Prevents cookie theft via Cross-Site Scripting (XSS).
  - `Secure`: Ensures cookies are never leaked over unencrypted plaintext Wi-Fi.
  - `SameSite`: Verifies `Strict` or `Lax` policy to defeat Cross-Site Request Forgery (CSRF).

### 4. 🎯 API & Hidden Attack Surface Discovery
- Automatically probes for exposed internal documentation:
  - `/swagger.json`, `/openapi.json`, `/api-docs`, `/v2/api-docs`, `/swagger-ui.html`.
  - Active GraphQL endpoints (`/graphql`) with schema verification.

### 5. 🛡️ Smart Anti-False-Positive Filter
- Disables blind redirect tracking (`allow_redirects=False`) to prevent 301/303 redirect pages from triggering false alarms.
- Content signature validation: `.env` or configuration dumps are only flagged if actual configuration keys match the payload body.

### 6. 🏆 Industry-Standard Security Scoring (Grade A+ to F)
- Computes a global Security Score (0–100) and Letter Grade (`A+`, `A`, `B`, `C`, `D`, `F`) inspired by Mozilla Observatory and Qualys SSL Labs.

### 7. 🚀 DevSecOps CI/CD Quality Gate
- Includes `--fail-on [HIGH|MEDIUM|LOW]` flag to automatically fail pull requests or deployments if critical vulnerabilities are detected.
- Includes pre-built `.github/workflows/security-audit.yml` GitHub Action.

---

## 📁 Architecture
```text
abliteration/
├── src/
│   ├── crawler.py       # Smart Web Spider & parameter extractor
│   ├── ssl_inspector.py # Cryptographic & SSL/TLS certificate auditor
│   ├── auditor.py       # Security checks, cookie hygiene, & scoring engine
│   └── reporter.py      # Terminal, JSON, & interactive HTML report generator
├── .github/
│   └── workflows/
│       └── security-audit.yml  # Automated CI/CD pipeline
├── OUTPUT/
│   ├── audit_report.html       # Visual executive HTML report
│   └── audit_report.json       # Machine-readable JSON report
├── requirements.txt
├── abliteration.py      # Main CLI entry point
└── README.md
```

---

## 🚀 Installation & Usage

```bash
git clone https://github.com/itzluthfi/abliteration.git
cd abliteration
pip install -r requirements.txt

# 1. Interactive Mode:
python abliteration.py

# 2. Command Line Execution:
python abliteration.py -u https://your-site.com --max-pages 20

# 3. CI/CD Quality Gate (Fail if HIGH risk is detected):
python abliteration.py -u https://your-site.com --fail-on HIGH
```

---

## 📄 Sample Report Output
After the audit finishes, open the interactive HTML report in your browser:
```text
====================================================================
          🛡️  ABLITERATION v3.1 - EXECUTIVE SECURITY AUDIT
====================================================================
Target URL     : https://fd-printing.sir-l.web.id
Security Grade : [ GRADE: B ] (75/100)
SSL/TLS Status : TLSv1.3 | Issuer: Google Trust Services (88 days left)
Pages Crawled  : 14
Forms Discovered: 12
Params Tested  : 9
--------------------------------------------------------------------
Risk Matrix    : [🔴 HIGH: 1]  [🟡 MEDIUM: 2]  [🔵 LOW: 2]  [⚪ INFO: 1]
====================================================================
```

---

## ⚖️ Disclaimer
This tool is built strictly for authorized security auditing, defensive security engineering, educational research, and internal website validation. Never audit systems without explicit written permission from the owner.

## 👤 Author
- **itzluthfi**
