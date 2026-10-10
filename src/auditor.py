import time
import urllib.parse
import re
import requests

class Colors:
    R = '\033[1;31m'; G = '\033[1;32m'; Y = '\033[1;33m'; B = '\033[1;34m'
    M = '\033[1;35m'; C = '\033[1;36m'; W = '\033[1;37m'
    BOLD = '\033[1m'; EN = '\033[0m'

class SecurityAuditor:
    """Enterprise-grade security auditor with anti-false-positive heuristics."""
    def __init__(self, target_url, session=None):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Abliteration-Auditor/3.0 (+https://github.com/itzluthfi/abliteration)'
        })
        self.findings = []  # List of dicts: {'category': str, 'level': 'HIGH'|'MEDIUM'|'LOW'|'INFO', 'title': str, 'detail': str, 'remediation': str}

    def log_finding(self, category, level, title, detail, remediation=""):
        self.findings.append({
            'category': category,
            'level': level,
            'title': title,
            'detail': detail,
            'remediation': remediation
        })

    # 1. Security Headers & Information Leakage
    def audit_headers_and_server(self):
        try:
            resp = self.session.get(self.target_url, timeout=10)
            headers = resp.headers
        except Exception as e:
            self.log_finding('Infrastructure', 'HIGH', 'Target Unreachable', str(e))
            return

        # Check Missing Security Headers
        req_headers = {
            'Strict-Transport-Security': ('HIGH', 'Force browser to use encrypted HTTPS (HSTS)', 'Strict-Transport-Security: max-age=31536000; includeSubDomains'),
            'Content-Security-Policy': ('MEDIUM', 'Prevent XSS and unauthorized script execution (CSP)', "Content-Security-Policy: default-src 'self'"),
            'X-Frame-Options': ('MEDIUM', 'Mitigate Clickjacking attacks by disallowing frame embedding', 'X-Frame-Options: DENY'),
            'X-Content-Type-Options': ('LOW', 'Prevent MIME-type sniffing', 'X-Content-Type-Options: nosniff'),
            'Referrer-Policy': ('LOW', 'Control leak of referrer URL', 'Referrer-Policy: strict-origin-when-cross-origin')
        }

        for h, (level, desc, fix) in req_headers.items():
            if h not in headers:
                self.log_finding('Security Headers', level, f'Missing {h}', f'{desc}. Header is not present.', f'Add header: {fix}')

        # Server / Tech Stack Information Disclosure
        leaky_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime']
        for lh in leaky_headers:
            if lh in headers:
                val = headers[lh]
                # If it leaks specific versions (e.g. PHP/8.1, Apache/2.4)
                if any(char.isdigit() for char in val):
                    self.log_finding('Information Disclosure', 'LOW', f'Technology Version Leak ({lh})', f'Reveals exact backend version: "{val}".', f'Disable or mask the {lh} response header in web server configuration.')

    # 2. CORS Misconfiguration Audit
    def audit_cors(self):
        evil_origin = 'https://evil-attacker.com'
        try:
            resp = self.session.get(self.target_url, headers={'Origin': evil_origin}, timeout=8)
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == evil_origin and acac.lower() == 'true':
                self.log_finding('CORS', 'HIGH', 'Overly Permissive CORS with Credentials', 
                                 f'Server reflects arbitrary origin "{evil_origin}" with Allow-Credentials: true. Allows cross-origin data theft.',
                                 'Explicitly whitelist trusted origins instead of reflecting user-supplied Origin.')
            elif acao == '*':
                self.log_finding('CORS', 'INFO', 'Wildcard CORS Header', 'Access-Control-Allow-Origin is set to "*". Acceptable for public APIs.')
        except Exception:
            pass

    # 3. Sensitive Files Audit with Anti-False-Positive Filter
    def audit_sensitive_files(self):
        targets = [
            ('.env', ['=', 'APP_', 'DB_', 'SECRET', 'KEY'], 'Environment configuration file with API keys/passwords'),
            ('.git/config', ['[core]', 'repositoryformatversion'], 'Git repository configuration exposure'),
            ('wp-config.php.bak', ['DB_NAME', 'DB_PASSWORD'], 'WordPress backup configuration'),
            ('backup.sql', ['CREATE TABLE', 'INSERT INTO', 'mysqldump'], 'Plaintext database dump'),
            ('composer.json', ['"require"', '"name"'], 'Composer dependency manifest'),
            ('package.json', ['"dependencies"', '"devDependencies"'], 'Node.js dependency manifest'),
            ('robots.txt', ['User-agent:', 'Disallow:'], 'Robots crawler policy')
        ]

        for path, signatures, desc in targets:
            url = f"{self.target_url}/{path.lstrip('/')}"
            try:
                # Do NOT follow redirects automatically to avoid false-positives
                resp = self.session.get(url, timeout=6, allow_redirects=False)

                # Check if server redirected (301, 302, 303, 307)
                if resp.status_code in [301, 302, 303, 307, 308]:
                    continue  # Safely redirected (e.g. to sign-in or home) - NOT vulnerable

                if resp.status_code == 200:
                    text = resp.text
                    content_type = resp.headers.get('Content-Type', '').lower()

                    # False positive check: if content-type is HTML, but this is a config file
                    if 'text/html' in content_type and path != 'robots.txt':
                        # Check if any actual signature is in text
                        has_sig = any(sig in text for sig in signatures)
                        if not has_sig:
                            continue  # False positive! It's just a 200 OK HTML error or landing page

                    level = 'INFO' if path == 'robots.txt' else 'HIGH'
                    self.log_finding('Sensitive Files', level, f'Exposed File: {path}', 
                                     f'{desc} is publicly accessible at {url} (HTTP 200).',
                                     f'Block web server access to {path} or remove it from public root.')
            except Exception:
                pass

    # 4. Context-Aware Dynamic Input Reflection Check (SQLi / XSS heuristics)
    def audit_dynamic_inputs(self, forms, params):
        # Test discovered URL query params
        test_payload_xss = 'ab1ite"r><svg/onload=alert(1)>'
        test_payload_sqli = "1' AND '1'='1"

        tested_params = set()
        for p in params:
            if p in tested_params:
                continue
            tested_params.add(p)

            # Test XSS Reflection
            test_url = f"{self.target_url}?{p}={urllib.parse.quote(test_payload_xss)}"
            try:
                resp = self.session.get(test_url, timeout=8)
                if test_payload_xss in resp.text:
                    self.log_finding('XSS', 'HIGH', f'Reflected XSS on parameter: {p}', 
                                     f'Payload "{test_payload_xss}" was reflected unescaped in response.',
                                     'Apply context-aware output encoding (HTML entity encoding) for user inputs.')
            except Exception:
                pass

            # Test SQLi Error Heuristic
            test_url_sqli = f"{self.target_url}?{p}={urllib.parse.quote(test_payload_sqli)}"
            try:
                start = time.time()
                resp = self.session.get(test_url_sqli, timeout=8)
                elapsed = time.time() - start
                
                # Check known DB error patterns
                db_errors = [
                    'you have an error in your sql syntax',
                    'warning: mysql_',
                    'unclosed quotation mark after the character string',
                    'postgresql error:',
                    'sqlite3.operationalerror',
                    'ora-00933: sql command not properly ended'
                ]
                txt_lower = resp.text.lower()
                for err in db_errors:
                    if err in txt_lower:
                        self.log_finding('SQL Injection', 'HIGH', f'SQL Syntax Error on parameter: {p}',
                                         f'Database error string detected: "{err}".',
                                         'Use Parameterized Queries / Prepared Statements (ORM / PDO).')
                        break
            except Exception:
                pass
