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
from src.reporter import Reporter

def banner():
    print(f"""
{Colors.BOLD}╔══════════════════════════════════════════════════════════╗
║   ABLITERATION v3.0 - Professional Web Security Auditor  ║
║   Enterprise DAST Engine & Anti-False-Positive Analyzer  ║
╚══════════════════════════════════════════════════════════╝{Colors.EN}
""")

def main():
    parser = argparse.ArgumentParser(description="Abliteration v3.0 Web Security Auditor")
    parser.add_argument("-u", "--url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--max-pages", type=int, default=15, help="Maximum pages for crawler to discover (default: 15)")
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

    print(f"\n{Colors.BOLD}[*] Initializing Audit on: {target}{Colors.EN}")

    # Phase 1: Smart Crawling
    print(f"{Colors.B}[1/4] Running Smart Web Spider (Max {args.max_pages} pages)...{Colors.EN}")
    crawler = Crawler(target, max_pages=args.max_pages)
    crawl_data = crawler.crawl()
    print(f"      ✓ Discovered {crawl_data['visited_count']} pages, {len(crawl_data['forms'])} forms, and {len(crawl_data['params'])} dynamic parameters.")

    # Phase 2: Security Auditing
    auditor = SecurityAuditor(target, session=crawler.session)

    print(f"{Colors.B}[2/4] Auditing Security Headers & Technology Leaks...{Colors.EN}")
    auditor.audit_headers_and_server()

    print(f"{Colors.B}[3/4] Scanning Sensitive Files (Anti-False-Positive Heuristics)...{Colors.EN}")
    auditor.audit_sensitive_files()

    print(f"{Colors.B}[4/4] Testing Dynamic Parameter Reflections & CORS...{Colors.EN}")
    auditor.audit_cors()
    auditor.audit_dynamic_inputs(crawl_data['forms'], crawl_data['params'])

    # Phase 3: Reporting
    reporter = Reporter(target, auditor.findings, crawl_data, output_dir=args.output)
    reporter.print_terminal_summary()

    json_path = reporter.export_json()
    html_path = reporter.export_html()

    print(f"\n{Colors.G}[✓] Audit complete!{Colors.EN}")
    print(f"    • HTML Report : {os.path.abspath(html_path)}")
    print(f"    • JSON Report : {os.path.abspath(json_path)}")

if __name__ == "__main__":
    main()
