# Abliteration V3.0 🛡️

**Abliteration** is an enterprise-grade, lightweight Dynamic Application Security Testing (DAST) engine and web security auditor designed for developers, security researchers, and automated CI/CD pipelines.

## 🌟 Key Upgrades in v3.0

Unlike simple single-URL toy scripts, **Abliteration v3.0** incorporates real-world application security testing concepts:

1. 🕷️ **Smart Web Spider / Crawler**: Automatically crawls internal links (`<a href>`), parses HTML forms (`<form>`), and extracts real query parameters.
2. 🛡️ **Anti-False-Positive Filter**:
   - Disables blind redirect tracking (`allow_redirects=False`) to avoid flagging 301/303 redirect pages as "exposed files".
   - Content signature validation: `.env` or configuration files are only flagged if actual configuration keys are detected in the body.
3. 🔒 **Enterprise Header & CORS Audit**:
   - Comprehensive audit of HSTS (`Strict-Transport-Security`), CSP (`Content-Security-Policy`), Clickjacking protection (`X-Frame-Options`), MIME sniffing (`X-Content-Type-Options`), and Referrer Policy.
   - CORS misconfiguration testing with reflected origin and credentials check.
4. 🎯 **Context-Aware Dynamic Parameter Testing**: Tests actual parameters and inputs discovered during the crawl phase for XSS and SQL injection reflection.
5. 📊 **Executive Multi-Format Reporting**: Generates interactive visual HTML reports (`OUTPUT/audit_report.html`) and structured JSON (`OUTPUT/audit_report.json`).

## 📁 Architecture
```text
abliteration/
├── src/
│   ├── crawler.py       # Smart Web Spider & parameter extractor
│   ├── auditor.py       # Security checks with anti-false-positive heuristics
│   └── reporter.py      # Terminal, JSON, & interactive HTML report generator
├── OUTPUT/
│   ├── audit_report.html
│   └── audit_report.json
├── requirements.txt
├── abliteration.py      # Main CLI entry point
└── README.md
```

## 🚀 Installation & Usage

```bash
git clone https://github.com/itzluthfi/abliteration.git
cd abliteration
pip install -r requirements.txt

# Run interactive mode:
python abliteration.py

# Or run with CLI arguments:
python abliteration.py -u https://your-site.com --max-pages 20
```

## 📄 Sample Report Output
After the audit finishes, inspect the interactive HTML report in your browser:
```text
[✓] Audit complete!
    • HTML Report : /abliteration/OUTPUT/audit_report.html
    • JSON Report : /abliteration/OUTPUT/audit_report.json
```

## ⚖️ Disclaimer
This tool is built strictly for authorized security auditing, defensive security engineering, educational research, and internal website validation. Never audit systems without explicit written permission from the owner.

## 👤 Author
- **itzluthfi**
