import requests
import urllib.parse

class DNSAndDefenseAuditor:
    """Audits Domain Email Spoofing defenses (SPF, DMARC), RFC 9116 security.txt, and WAF fingerprinting."""
    def __init__(self, target_url, timeout=6):
        parsed = urllib.parse.urlparse(target_url)
        self.hostname = parsed.hostname or target_url
        # Extract root registered domain if possible (e.g. sub.domain.com -> domain.com)
        parts = self.hostname.split('.')
        if len(parts) >= 2:
            self.root_domain = ".".join(parts[-2:]) if len(parts) == 2 or len(parts[-1]) > 2 else ".".join(parts[-3:])
        else:
            self.root_domain = self.hostname
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Abliteration-Auditor/3.3 (+https://github.com/itzluthfi/abliteration)',
            'Accept': 'application/dns-json'
        })

    def query_dns_txt(self, name):
        """Queries DNS TXT records via Cloudflare DoH (DNS over HTTPS)."""
        try:
            url = f"https://cloudflare-dns.com/dns-query?name={name}&type=TXT"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get('Answer', [])
                return [a.get('data', '').strip('"') for a in answers if a.get('type') == 16]
        except Exception:
            pass
        return []

    def audit_email_security(self):
        """Audits SPF and DMARC for Email Spoofing & Phishing vulnerability."""
        findings = []
        domain = self.hostname

        # 1. Audit SPF
        spf_records = [r for r in self.query_dns_txt(domain) if r.startswith('v=spf1')]
        if not spf_records and domain != self.root_domain:
            spf_records = [r for r in self.query_dns_txt(self.root_domain) if r.startswith('v=spf1')]

        if not spf_records:
            poc = f'curl -s -H "Accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name={domain}&type=TXT"'
            findings.append({
                'category': 'Email Security',
                'level': 'HIGH',
                'title': 'Missing SPF (Sender Policy Framework) Record',
                'detail': f'Domain "{domain}" has no SPF record published. Attackers can forge emails appearing from @{domain}.',
                'remediation': 'Publish a DNS TXT record for SPF: "v=spf1 mx ~all" or your designated mail servers.',
                'poc_curl': poc,
                'evidence_snippet': 'No TXT record starting with "v=spf1" found.'
            })

        # 2. Audit DMARC
        dmarc_name = f"_dmarc.{domain}"
        dmarc_records = [r for r in self.query_dns_txt(dmarc_name) if r.startswith('v=DMARC1')]
        if not dmarc_records and domain != self.root_domain:
            dmarc_name = f"_dmarc.{self.root_domain}"
            dmarc_records = [r for r in self.query_dns_txt(dmarc_name) if r.startswith('v=DMARC1')]

        if not dmarc_records:
            poc = f'curl -s -H "Accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name={dmarc_name}&type=TXT"'
            findings.append({
                'category': 'Email Security',
                'level': 'HIGH',
                'title': 'Missing DMARC Record (Susceptible to Email Spoofing)',
                'detail': f'Domain has no DMARC record at "{dmarc_name}". Mail servers will not reject unauthorized emails sent under your domain.',
                'remediation': f'Add a DNS TXT record at {dmarc_name} with value: "v=DMARC1; p=reject; rua=mailto:dmarc@{self.root_domain}"',
                'poc_curl': poc,
                'evidence_snippet': f'DNS query for {dmarc_name} returned no DMARC record.'
            })
        else:
            dmarc_val = dmarc_records[0]
            if 'p=none' in dmarc_val:
                findings.append({
                    'category': 'Email Security',
                    'level': 'MEDIUM',
                    'title': 'Permissive DMARC Policy (p=none)',
                    'detail': f'DMARC policy is set to "p=none". Phishing emails impersonating your domain are monitored but NOT rejected by recipient mail servers.',
                    'remediation': 'Upgrade your DMARC policy from "p=none" to "p=quarantine" or "p=reject".',
                    'poc_curl': f'curl -s -H "Accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name={dmarc_name}&type=TXT"',
                    'evidence_snippet': dmarc_val
                })

        return findings

    def audit_security_txt(self, base_url):
        """Audits RFC 9116 security.txt contact file."""
        findings = []
        paths = ['/.well-known/security.txt', '/security.txt']
        found = False

        for p in paths:
            url = f"{base_url.rstrip('/')}{p}"
            try:
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and ('Contact:' in resp.text or 'Expires:' in resp.text):
                    found = True
                    break
            except Exception:
                pass

        if not found:
            findings.append({
                'category': 'Compliance',
                'level': 'LOW',
                'title': 'Missing RFC 9116 security.txt',
                'detail': 'Website lacks a standardized security vulnerability disclosure policy at /.well-known/security.txt.',
                'remediation': 'Create /.well-known/security.txt containing Contact: and Expires: directives per RFC 9116.',
                'poc_curl': f'curl -s -i "{base_url.rstrip("/")}/.well-known/security.txt"',
                'evidence_snippet': 'File /.well-known/security.txt does not exist or returned non-200 status.'
            })

        return findings

    def detect_waf(self, headers):
        """Fingerprints Web Application Firewall (WAF) or CDN."""
        headers_str = str(headers).lower()

        if 'cloudflare' in headers_str or 'cf-ray' in headers_str:
            return 'Cloudflare (WAF/CDN)'
        if 'akamai' in headers_str:
            return 'Akamai Edge (WAF/CDN)'
        if 'cloudfront' in headers_str or 'x-amz-cf-id' in headers_str:
            return 'AWS CloudFront'
        if 'fastly' in headers_str:
            return 'Fastly CDN'
        if 'imperva' in headers_str or 'incap_ses' in headers_str:
            return 'Imperva / Incapsula'
        if 'sucuri' in headers_str:
            return 'Sucuri CloudProxy'

        server = headers.get('Server', '')
        if server:
            return f'Standard Web Server ({server})'

        return 'Direct / Undetected'
