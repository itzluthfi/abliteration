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
from src.tools.dns_auditor import DNSAndDefenseAuditor
from src.tools.tempmail import TempMailClient
from src.reporter import Reporter

def banner():
    print(f"""
{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗
║   ABLITERATION v3.3 - Enterprise Web Security Platform       ║
║   Advanced DAST, Cryptography, DNS/DMARC & OAST Temp-Mail    ║
╚══════════════════════════════════════════════════════════════╝{Colors.EN}
""")

def main():
    parser = argparse.ArgumentParser(description="Abliteration v3.3 Enterprise Web Security Platform")
    parser.add_argument("-u", "--url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--max-pages", type=int, default=15, help="Maximum pages for crawler to discover (default: 15)")
    parser.add_argument("--fail-on", choices=['HIGH', 'MEDIUM', 'LOW'], help="CI/CD Quality Gate: exit with code 1 if finding of level or higher is found")
    parser.add_argument("--temp-mail", action="store_true", help="Generate a disposable inbox for OAST & registration testing")
    parser.add_argument("--listen-sec", type=int, default=60, help="Listening duration for temp-mail in seconds (default: 60)")
    parser.add_argument("--output", default="OUTPUT", help="Output directory for reports (default: OUTPUT)")
    args = parser.parse_args()

    banner()

    # Standalone Tool: Disposable Email Engine
    if args.temp_mail:
        print(f"{Colors.BOLD}[*] Launching Abliteration OAST Disposable Email Engine...{Colors.EN}")
        try:
            client = TempMailClient()
            email = client.create_inbox()
            print(f"\n{Colors.G}[✓] Active Disposable Inbox Created!{Colors.EN}")
            print(f"    • Email Address : {Colors.BOLD}{email}{Colors.EN}")
            print(f"    • API Provider  : mail.tm fleet\n")
            client.listen(duration_sec=args.listen_sec)
        except Exception as e:
            print(f"{Colors.R}[!] Failed to initialize disposable email: {e}{Colors.EN}")
        return

    target = args.url
    if not target:
        try:
            target = input(f"{Colors.C}[>] Input Target URL (or type 'mail' for Temp Mail){Colors.EN}: ").strip()
            if target.lower() == 'mail':
                client = TempMailClient()
                email = client.create_inbox()
                print(f"\n{Colors.G}[✓] Active Disposable Inbox : {email}{Colors.EN}")
                client.listen(duration_sec=60)
                return
        except KeyboardInterrupt:
            print("\nAborted.")
            return

    if not target:
        target = "https://example.com"
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    target = target.rstrip('/')

    print(f"\n{Colors.BOLD}[*] Initializing Comprehensive Security Audit on: {target}{Colors.EN}")

    # Phase 1: Smart Crawling
    print(f"{Colors.B}[1/6] Running Smart Web Spider (Max {args.max_pages} pages)...{Colors.EN}")
    crawler = Crawler(target, max_pages=args.max_pages)
    crawl_data = crawler.crawl()
    print(f"      ✓ Discovered {crawl_data['visited_count']} pages, {len(crawl_data['forms'])} forms, and {len(crawl_data['params'])} dynamic parameters.")

    # Phase 2: Cryptographic & SSL/TLS Audit
    print(f"{Colors.B}[2/6] Inspecting SSL/TLS Certificate & Cryptographic Ciphers...{Colors.EN}")
    ssl_inspector = SSLInspector(target)
    ssl_data = ssl_inspector.inspect()
    
    auditor = SecurityAuditor(target, session=crawler.session)
    for sf in ssl_data.get('findings', []):
        auditor.log_finding(sf['category'], sf['level'], sf['title'], sf['detail'], sf.get('remediation', ''), sf.get('poc_curl', ''), sf.get('evidence_snippet', ''))

    # Phase 3: DNS, SPF/DMARC Spoofing, & WAF Detection
    print(f"{Colors.B}[3/6] Auditing DNS Spoofing (SPF/DMARC), RFC 9116 & WAF Perimeter...{Colors.EN}")
    dns_auditor = DNSAndDefenseAuditor(target)
    email_findings = dns_auditor.audit_email_security()
    for ef in email_findings:
        auditor.log_finding(ef['category'], ef['level'], ef['title'], ef['detail'], ef.get('remediation', ''), ef.get('poc_curl', ''), ef.get('evidence_snippet', ''))

    sec_txt_findings = dns_auditor.audit_security_txt(target)
    for stf in sec_txt_findings:
        auditor.log_finding(stf['category'], stf['level'], stf['title'], stf['detail'], stf.get('remediation', ''), stf.get('poc_curl', ''), stf.get('evidence_snippet', ''))

    try:
        home_resp = crawler.session.get(target, timeout=8)
        waf_name = dns_auditor.detect_waf(home_resp.headers)
    except Exception:
        waf_name = "Undetected"

    # Phase 4: Security Headers & Cookie Security
    print(f"{Colors.B}[4/6] Auditing Security Headers & Cookie Hygiene...{Colors.EN}")
    auditor.audit_headers_and_server()
    auditor.audit_cookies()

    # Phase 5: Sensitive Files & API Discovery (Anti-False-Positive)
    print(f"{Colors.B}[5/6] Probing Sensitive Exposure, Hidden APIs & Swagger...{Colors.EN}")
    auditor.audit_sensitive_files()
    auditor.audit_api_surface()

    # Phase 6: Dynamic Parameter Reflections & CORS
    print(f"{Colors.B}[6/6] Testing Dynamic Parameter Reflections & CORS...{Colors.EN}")
    auditor.audit_cors()
    auditor.audit_dynamic_inputs(crawl_data['forms'], crawl_data['params'])

    # Score calculation & Reporting
    score, grade = auditor.calculate_score()
    reporter = Reporter(target, auditor.findings, crawl_data, ssl_data=ssl_data, waf_name=waf_name, score=score, grade=grade, output_dir=args.output)
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
