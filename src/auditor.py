import time
import urllib.parse
import re
import requests

class Colors:
    R = '\033[1;31m'; G = '\033[1;32m'; Y = '\033[1;33m'; B = '\033[1;34m'
    M = '\033[1;35m'; C = '\033[1;36m'; W = '\033[1;37m'
    BOLD = '\033[1m'; EN = '\033[0m'

class SecurityAuditor:
    """Enterprise-grade security auditor with Evidence-Backed Proof of Concept (PoC)."""
    def __init__(self, target_url, session=None):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Abliteration-Auditor/3.2 (+https://github.com/itzluthfi/abliteration)'
        })
        self.findings = []
        self.cert_info = {}

    def log_finding(self, category, level, title, detail, remediation="", poc_curl="", evidence_snippet=""):
        """Logs a finding backed by reproducible evidence (PoC)."""
        self.findings.append({
            'category': category,
            'level': level,
            'title': title,
            'detail': detail,
            'remediation': remediation,
            'poc_curl': poc_curl,
            'evidence_snippet': evidence_snippet
        })

    def calculate_score(self):
        score = 100
        for f in self.findings:
            if f['level'] == 'HIGH':
                score -= 20
            elif f['level'] == 'MEDIUM':
                score -= 10
            elif f['level'] == 'LOW':
                score -= 5

        score = max(0, min(100, score))
        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 65:
            grade = "C"
        elif score >= 50:
            grade = "D"
        else:
            grade = "F"

        return score, grade

    # 1. Security Headers Audit with Real PoC curl command
    def audit_headers_and_server(self):
        try:
            resp = self.session.get(self.target_url, timeout=10)
            headers = resp.headers
        except Exception as e:
            self.log_finding('Infrastructure', 'HIGH', 'Target Unreachable', str(e),
                             poc_curl=f'curl -I -v "{self.target_url}"',
                             evidence_snippet=f'Network error: {str(e)}')
            return

        req_headers = {
            'Strict-Transport-Security': ('HIGH', 'Force browser to use encrypted HTTPS (HSTS)', 'Strict-Transport-Security: max-age=31536000; includeSubDomains'),
            'Content-Security-Policy': ('MEDIUM', 'Prevent XSS and unauthorized script execution (CSP)', "Content-Security-Policy: default-src 'self'"),
            'X-Frame-Options': ('MEDIUM', 'Mitigate Clickjacking attacks by disallowing frame embedding', 'X-Frame-Options: DENY'),
            'X-Content-Type-Options': ('LOW', 'Prevent MIME-type sniffing', 'X-Content-Type-Options: nosniff'),
            'Referrer-Policy': ('LOW', 'Control leak of referrer URL', 'Referrer-Policy: strict-origin-when-cross-origin'),
            'Permissions-Policy': ('LOW', 'Restrict sensitive browser features (camera, mic, geolocation)', 'Permissions-Policy: camera=(), microphone=(), geolocation=()')
        }

        # Build raw header proof
        header_sample = "\n".join([f"{k}: {v}" for k, v in list(headers.items())[:6]])

        for h, (level, desc, fix) in req_headers.items():
            if h not in headers:
                poc = f'curl -I -s "{self.target_url}" | grep -i "{h}"'
                self.log_finding(
                    category='Security Headers',
                    level=level,
                    title=f'Missing {h}',
                    detail=f'{desc}. Header is absent from server response.',
                    remediation=f'Add header: {fix}',
                    poc_curl=poc,
                    evidence_snippet=f'Verified via HTTP response inspection. No "{h}" header returned by {self.target_url}.'
                )

        # Server Technology Version Disclosure
        leaky_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime']
        for lh in leaky_headers:
            if lh in headers:
                val = headers[lh]
                if any(char.isdigit() for char in val):
                    poc = f'curl -I -s "{self.target_url}" | grep -i "{lh}"'
                    self.log_finding(
                        category='Information Disclosure',
                        level='LOW',
                        title=f'Technology Version Leak ({lh})',
                        detail=f'Server explicitly reveals exact backend version: "{lh}: {val}".',
                        remediation=f'Disable or mask the {lh} response header in your web server configuration.',
                        poc_curl=poc,
                        evidence_snippet=f'{lh}: {val}'
                    )

    # 2. Cookie Security Hygiene Audit with Evidence
    def audit_cookies(self):
        try:
            resp = self.session.get(self.target_url, timeout=8)
            cookies = resp.cookies
            raw_set_cookie = resp.headers.get('set-cookie', '')

            if not cookies and not raw_set_cookie:
                return

            for cookie in cookies:
                c_name = cookie.name
                is_httponly = cookie.has_nonstandard_attr('httponly') or 'httponly' in str(cookie._rest).lower() or f"{c_name}=" in raw_set_cookie and 'httponly' in raw_set_cookie.lower()
                if not is_httponly:
                    poc = f'curl -I -s "{self.target_url}" | grep -i "set-cookie"'
                    self.log_finding(
                        category='Cookie Security',
                        level='MEDIUM',
                        title=f'Cookie Missing HttpOnly Flag: "{c_name}"',
                        detail=f'Cookie "{c_name}" is readable via JavaScript (document.cookie). Can be stolen in XSS attacks.',
                        remediation=f'Set the "HttpOnly" directive when issuing the {c_name} cookie.',
                        poc_curl=poc,
                        evidence_snippet=f'Set-Cookie directive for "{c_name}" does not contain the HttpOnly flag.'
                    )

                is_secure = cookie.secure or (f"{c_name}=" in raw_set_cookie and 'secure' in raw_set_cookie.lower())
                if not is_secure and self.target_url.startswith('https'):
                    poc = f'curl -I -s "{self.target_url}" | grep -i "set-cookie"'
                    self.log_finding(
                        category='Cookie Security',
                        level='MEDIUM',
                        title=f'Cookie Missing Secure Flag: "{c_name}"',
                        detail=f'Cookie "{c_name}" can be transmitted over unencrypted plaintext HTTP connections.',
                        remediation=f'Set the "Secure" directive when issuing the {c_name} cookie.',
                        poc_curl=poc,
                        evidence_snippet=f'Set-Cookie directive for "{c_name}" does not contain the Secure flag.'
                    )
        except Exception:
            pass

    # 3. API & Hidden Surface Discovery with PoC
    def audit_api_surface(self):
        endpoints = [
            ('/swagger.json', ['"swagger":', '"openapi":'], 'Swagger/OpenAPI 2.0/3.0 Definition'),
            ('/openapi.json', ['"openapi":', '"paths":'], 'OpenAPI 3.0 Specification'),
            ('/api-docs', ['"openapi":', '"swagger":', 'swagger-ui'], 'Interactive API Documentation'),
            ('/v2/api-docs', ['"swagger":', '"paths":'], 'Springfox Swagger v2 API Docs'),
            ('/swagger/index.html', ['swagger-ui', 'swagger-ui-bundle'], 'Swagger UI Interactive Console'),
            ('/graphql', ['"errors"', '"data"', '__schema'], 'GraphQL Endpoint')
        ]

        for path, signatures, desc in endpoints:
            url = f"{self.target_url}/{path.lstrip('/')}"
            try:
                resp = self.session.get(url, timeout=6, allow_redirects=False)
                if resp.status_code == 200:
                    text = resp.text
                    has_sig = any(sig in text for sig in signatures)
                    if has_sig:
                        match_sample = text[:150].replace('\n', ' ')
                        poc = f'curl -s -i "{url}"'
                        self.log_finding(
                            category='API Exposure',
                            level='MEDIUM',
                            title=f'Exposed API Surface: {path}',
                            detail=f'{desc} is publicly accessible at {url}. Exposes full internal endpoint schemas.',
                            remediation=f'Restrict access to {path} to authorized internal environments or VPN.',
                            poc_curl=poc,
                            evidence_snippet=f'HTTP 200 OK | Body: {match_sample}...'
                        )
                        continue

                if path == '/graphql':
                    gql_resp = self.session.post(url, json={"query": "{__typename}"}, timeout=6, allow_redirects=False)
                    if gql_resp.status_code == 200 and 'data' in gql_resp.text:
                        poc = f'curl -s -X POST "{url}" -H "Content-Type: application/json" -d \'{{"query": "{{__typename}}"}}\''
                        self.log_finding(
                            category='API Exposure',
                            level='MEDIUM',
                            title='Active GraphQL Endpoint Exposed',
                            detail=f'GraphQL endpoint active at {url}. Responded to GraphQL query introspection.',
                            remediation='Disable GraphQL Introspection in production and implement depth/rate limiting.',
                            poc_curl=poc,
                            evidence_snippet=gql_resp.text[:150]
                        )
            except Exception:
                pass

    # 4. Sensitive Files Audit with Evidence Proof
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
                resp = self.session.get(url, timeout=6, allow_redirects=False)

                if resp.status_code in [301, 302, 303, 307, 308]:
                    continue

                if resp.status_code == 200:
                    text = resp.text
                    content_type = resp.headers.get('Content-Type', '').lower()

                    if 'text/html' in content_type and path != 'robots.txt':
                        has_sig = any(sig in text for sig in signatures)
                        if not has_sig:
                            continue

                    level = 'INFO' if path == 'robots.txt' else 'HIGH'
                    poc = f'curl -s -i "{url}"'
                    snippet = text[:120].replace('\n', ' ')
                    self.log_finding(
                        category='Sensitive Files',
                        level=level,
                        title=f'Exposed File: {path}',
                        detail=f'{desc} is publicly accessible at {url} (HTTP 200).',
                        remediation=f'Block web server access to {path} or remove it from public root.',
                        poc_curl=poc,
                        evidence_snippet=f'HTTP 200 OK | {snippet}...'
                    )
            except Exception:
                pass

    # 5. Dynamic Reflection Audit with Reproduction Proof
    def audit_dynamic_inputs(self, forms, params):
        test_payload_xss = 'ab1ite"r><svg/onload=alert(1)>'
        test_payload_sqli = "1' AND '1'='1"

        tested_params = set()
        for p in params:
            if p in tested_params:
                continue
            tested_params.add(p)

            # Test XSS Reflection with PoC
            test_url = f"{self.target_url}?{p}={urllib.parse.quote(test_payload_xss)}"
            try:
                resp = self.session.get(test_url, timeout=8)
                if test_payload_xss in resp.text:
                    poc = f'curl -s "{test_url}" | grep -F "{test_payload_xss}"'
                    self.log_finding(
                        category='XSS',
                        level='HIGH',
                        title=f'Reflected XSS on parameter: {p}',
                        detail=f'Payload was reflected unescaped in server response HTML.',
                        remediation='Apply context-aware output encoding (HTML entity encoding) for user inputs.',
                        poc_curl=poc,
                        evidence_snippet=f'Server reflected unescaped payload: "{test_payload_xss}"'
                    )
            except Exception:
                pass

            # Test SQLi Error Heuristic with PoC
            test_url_sqli = f"{self.target_url}?{p}={urllib.parse.quote(test_payload_sqli)}"
            try:
                resp = self.session.get(test_url_sqli, timeout=8)
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
                        poc = f'curl -s "{test_url_sqli}" | grep -i "{err}"'
                        self.log_finding(
                            category='SQL Injection',
                            level='HIGH',
                            title=f'SQL Syntax Error on parameter: {p}',
                            detail=f'Database error string detected in response: "{err}".',
                            remediation='Use Parameterized Queries / Prepared Statements (ORM / PDO).',
                            poc_curl=poc,
                            evidence_snippet=f'Observed database error in response: "{err}"'
                        )
                        break
            except Exception:
                pass

    # 6. CORS Audit with Proof
    def audit_cors(self):
        evil_origin = 'https://evil-attacker.com'
        try:
            resp = self.session.get(self.target_url, headers={'Origin': evil_origin}, timeout=8)
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == evil_origin and acac.lower() == 'true':
                poc = f'curl -I -s -H "Origin: {evil_origin}" "{self.target_url}" | grep -i "access-control"'
                self.log_finding(
                    category='CORS',
                    level='HIGH',
                    title='Overly Permissive CORS with Credentials',
                    detail=f'Server reflects arbitrary origin "{evil_origin}" with Allow-Credentials: true. Allows cross-origin data theft.',
                    remediation='Explicitly whitelist trusted origins instead of reflecting user-supplied Origin.',
                    poc_curl=poc,
                    evidence_snippet=f'Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}'
                )
        except Exception:
            pass
