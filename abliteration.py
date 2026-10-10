#!/usr/bin/env python3
import os
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from src.core import Colors
from src.scanner import scan_all

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{Colors.BOLD}╔══════════════════════════════════════════════════════╗
║  ABLITERATION v2.0 - Professional Web Scanner        ║
║  Advanced Detection & Security Assessment Module     ║
╚══════════════════════════════════════════════════════╝{Colors.EN}
""")

def main():
    banner()
    target = input(f"{Colors.C}[>] Input Target URL (e.g., https://site.com){Colors.EN}: ").strip()
    if not target:
        target = "https://example.com"
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    results, url = scan_all(target)

    # Summary Table
    print("\n" + "=" * 55)
    print(f"{Colors.BOLD}VULNERABILITY SUMMARY{Colors.EN}")
    print("=" * 55)
    for k, v in results.items():
        status = f"{Colors.R}⚠️ FOUND{Colors.EN}" if ("Detected" in str(v) or "Missing" in str(v) or "Vulnerable" in str(v)) else f"{Colors.G}✓ SAFE{Colors.EN}"
        print(f"• {k:<20}: {status} ({v})")
    print("=" * 55)

if __name__ == "__main__":
    main()
