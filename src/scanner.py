import os
import sys
import threading

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.core import Exploiter, Colors

def scan_all(target, result_file="OUTPUT/scan_result.txt"):
    print(f"\n{Colors.BOLD}═══ Starting Scan: {target} ═══{Colors.EN}\n")
    
    scanner = Exploiter(target)
    checks = [
        scanner.test_sqli,
        scanner.test_xss,
        scanner.test_idor,
        scanner.test_csrf,
        scanner.test_lfi,
        scanner.test_dorking,
        scanner.test_headers
    ]

    threads = []
    for check in checks:
        t = threading.Thread(target=check)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()

    # Generate Report
    os.makedirs(os.path.dirname(result_file) if os.path.dirname(result_file) else "OUTPUT", exist_ok=True)
    with open(result_file, 'w', encoding='utf-8') as f:
        f.write(f"TARGET: {target}\n\n")
        for k, v in scanner.results.items():
            f.write(f"{k}: {v}\n")
    
    print(f"\n{Colors.G}✓ Scan Complete! Report saved to {result_file}{Colors.EN}")
    return scanner.results, target
