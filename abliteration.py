#!/usr/bin/env python3
import os
import sys
import argparse

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from src.crawler import Crawler
from src.auditor import SecurityAuditor, Colors
from src.ssl_inspector import SSLInspector
from src.reporter import Reporter

def banner():
    print(f"""
{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗
║   ABLITERATION v3.1 - Enterprise Web Security Auditor        ║
║   Advanced DAST, Cryptographic Inspector & Security Scoring  ║
╚══════════════════════════════════════════════════════════════╝{Colors.EN}
""")

def main():
    parser = argparse.ArgumentParser(description="Abliteration v3.1 Enterprise Web Security Auditor")
    parser.add_argument("-u", "--url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--max-pages", type=int, default=15, help="Maximum pages for crawler to discover (default: 15)")
    parser.add_argument("--fail-on", choices=['HIGH', 'MEDIUM', 'LOW'], help="CI/CD Quality Gate: exit with code 1 if finding of level or higher is found")
    parser.add_argument("--output", default="OUTPUT", help="Output directory for reports (default: OUTPUT)")
    args = parser.parse_args()

    banner()

    target = args.url
    if not target:
        try:
            target = input(f"{Colors.C}[>] Input Target URL (e.g., https://site.com){Colors.EN}: ").strip()
        except KeyboardInterrupt:
            print("\nAborted.")
            return

    if not target:
        target = "https://example.com"
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    target = target.rstrip('/')

    print(f"\n{Colors.BOLD}[*] Initializing Enterprise Security Audit on: {target}{Colors.EN}")

    # Phase 1: Smart Crawling
    print(f"{Colors.B}[1/5] Running Smart Web Spider (Max {args.max_pages} pages)...{Colors.EN}")
    crawler = Crawler(target, max_pages=args.max_pages)
    crawl_data = crawler.crawl()
    print(f"      ✓ Discovered {crawl_data['visited_count']} pages, {len(crawl_data['forms'])} forms, and {len(crawl_data['params'])} dynamic parameters.")

    # Phase 2: Cryptographic & SSL/TLS Audit
    print(f"{Colors.B}[2/5] Inspecting SSL/TLS Certificate & Cryptographic Ciphers...{Colors.EN}")
    ssl_inspector = SSLInspector(target)
    ssl_data = ssl_inspector.inspect()
    
    auditor = SecurityAuditor(target, session=crawler.session)
    for sf in ssl_data.get('findings', []):
        auditor.log_finding(sf['category'], sf['level'], sf['title'], sf['detail'], sf.get('remediation', ''))

    # Phase 3: Security Headers & Cookie Security
    print(f"{Colors.B}[3/5] Auditing Security Headers & Cookie Hygiene...{Colors.EN}")
    auditor.audit_headers_and_server()
    auditor.audit_cookies()

    # Phase 4: Sensitive Files & API Discovery (Anti-False-Positive)
    print(f"{Colors.B}[4/5] Probing Sensitive Exposure, Hidden APIs & Swagger...{Colors.EN}")
    auditor.audit_sensitive_files()
    auditor.audit_api_surface()

    # Phase 5: Dynamic Parameter Reflections & CORS
    print(f"{Colors.B}[5/5] Testing Dynamic Parameter Reflections & CORS...{Colors.EN}")
    auditor.audit_cors()
    auditor.audit_dynamic_inputs(crawl_data['forms'], crawl_data['params'])

    # Score calculation & Reporting
    score, grade = auditor.calculate_score()
    reporter = Reporter(target, auditor.findings, crawl_data, ssl_data=ssl_data, score=score, grade=grade, output_dir=args.output)
    reporter.print_terminal_summary()

    json_path = reporter.export_json()
    html_path = reporter.export_html()

    print(f"\n{Colors.G}[✓] Audit complete!{Colors.EN}")
    print(f"    • Interactive HTML Report : {os.path.abspath(html_path)}")
    print(f"    • Structured JSON Report  : {os.path.abspath(json_path)}")

    # CI/CD Quality Gate logic
    if args.fail_on:
        severity_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        threshold = severity_order.get(args.fail_on, 3)
        has_violations = any(severity_order.get(f['level'], 0) >= threshold for f in auditor.findings)
        if has_violations:
            print(f"\n{Colors.R}[!] CI/CD Quality Gate FAILED: Found vulnerabilities at or above level {args.fail_on}. Exiting with code 1.{Colors.EN}")
            sys.exit(1)
        else:
            print(f"\n{Colors.G}[✓] CI/CD Quality Gate PASSED: No vulnerabilities at or above level {args.fail_on}.{Colors.EN}")

if __name__ == "__main__":
    main()
