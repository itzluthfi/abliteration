#!/usr/bin/env python3
import requests, os
from datetime import datetime

class Color:
    OK = '\033[92m'
    WARN = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def banner():
    print(f"{Color.BOLD}╔════════════════════════════════╗{Color.END}")
    print(f"{Color.BOLD}║   ABLITERATION (Web Scanner)   ║{Color.END}")
    print(f"{Color.BOLD}╚════════════════════════════════╝{Color.END}")

def fetch(url):
    try:
        return requests.get(url, timeout=10)
    except:
        return None

def check_sqli(url):
    try:
        r = requests.get(f"{url}?id=1'", timeout=10)
        if "sql" in r.text.lower() or "mysql" in r.text.lower():
            print(f"{Color.FAIL}⚠️  SQLi Detected{Color.END}")
        else:
            print(f"{Color.OK}✓ Safe from basic SQLi reflection{Color.END}")
    except Exception as e:
        print(f"{Color.WARN}⚠️ Error: {e}{Color.END}")

def check_xss(url):
    try:
        r = requests.get(f"{url}?name=<script>", timeout=10)
        if "<script>" in r.text:
            print(f"{Color.FAIL}⚠️  XSS Detected{Color.END}")
        else:
            print(f"{Color.OK}✓ Safe from basic XSS reflection{Color.END}")
    except Exception as e:
        print(f"{Color.WARN}⚠️ Error: {e}{Color.END}")

def main():
    banner()
    url = input(f"\n{Color.BOLD}Masukkan URL Target: {Color.END}").strip()
    if not url:
        print("URL tidak boleh kosong.")
        return
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    
    print("\nScanning...")
    check_sqli(url)
    check_xss(url)
    
    os.makedirs("OUTPUT", exist_ok=True)
    with open("OUTPUT/log.txt", "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now()}] Scan pada: {url}\n")
    print(f"\n{Color.OK}Selesai! Log tersimpan di OUTPUT/log.txt{Color.END}")

if __name__ == "__main__":
    main()
