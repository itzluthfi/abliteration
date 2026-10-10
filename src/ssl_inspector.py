import socket
import ssl
import urllib.parse
from datetime import datetime

class SSLInspector:
    """Enterprise-grade SSL/TLS Certificate and Cryptographic Protocol Auditor."""
    def __init__(self, target_url, timeout=6):
        parsed = urllib.parse.urlparse(target_url)
        self.hostname = parsed.hostname or target_url
        self.port = parsed.port or (443 if parsed.scheme == 'https' or not parsed.scheme else 80)
        self.is_https = parsed.scheme == 'https' or self.port == 443
        self.timeout = timeout

    def inspect(self):
        if not self.is_https:
            return {
                'enabled': False,
                'findings': [{
                    'category': 'SSL/TLS',
                    'level': 'HIGH',
                    'title': 'Unencrypted HTTP Protocol',
                    'detail': 'Website is running over plaintext HTTP without SSL/TLS encryption. All traffic can be intercepted (MitM).',
                    'remediation': 'Install an SSL certificate and redirect all HTTP traffic to HTTPS.'
                }]
            }

        findings = []
        cert_info = {}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher_name, proto, bits = ssock.cipher()

                    cert_info['tls_version'] = tls_version
                    cert_info['cipher'] = cipher_name
                    cert_info['cipher_bits'] = bits

                    # 1. Parse Expiration
                    not_after_str = cert.get('notAfter')
                    if not_after_str:
                        not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                        days_left = (not_after - datetime.utcnow()).days
                        cert_info['days_left'] = days_left
                        cert_info['expires_at'] = not_after.strftime('%Y-%m-%d')

                        if days_left < 0:
                            findings.append({
                                'category': 'SSL/TLS',
                                'level': 'HIGH',
                                'title': 'SSL Certificate Expired',
                                'detail': f'The SSL certificate expired {abs(days_left)} days ago on {cert_info["expires_at"]}.',
                                'remediation': 'Renew and deploy a valid SSL/TLS certificate immediately.'
                            })
                        elif days_left < 15:
                            findings.append({
                                'category': 'SSL/TLS',
                                'level': 'MEDIUM',
                                'title': 'SSL Certificate Expiring Soon',
                                'detail': f'The SSL certificate will expire in {days_left} days on {cert_info["expires_at"]}.',
                                'remediation': 'Schedule certificate renewal before expiration to avoid service interruption.'
                            })

                    # 2. Parse Issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    cert_info['issuer'] = issuer.get('organizationName') or issuer.get('commonName') or 'Unknown Issuer'

                    # 3. Audit TLS Version
                    if tls_version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        findings.append({
                            'category': 'SSL/TLS',
                            'level': 'HIGH',
                            'title': f'Deprecated Protocol ({tls_version}) Supported',
                            'detail': f'The server negotiates deprecated {tls_version}, which is vulnerable to POODLE, BEAST, and Sweet32 attacks.',
                            'remediation': 'Disable TLS 1.0/1.1 and SSLv3 in web server/load balancer. Enforce TLS 1.2 and TLS 1.3 only.'
                        })

                    # 4. Weak Cipher check
                    if bits and bits < 128:
                        findings.append({
                            'category': 'SSL/TLS',
                            'level': 'HIGH',
                            'title': f'Weak Cryptographic Cipher ({cipher_name})',
                            'detail': f'Server uses a weak encryption key length of only {bits} bits.',
                            'remediation': 'Configure strong cipher suites (AES-GCM, CHACHA20-POLY1305 with >= 128-bit key).'
                        })

            return {
                'enabled': True,
                'cert_info': cert_info,
                'findings': findings
            }

        except ssl.SSLCertVerificationError as e:
            return {
                'enabled': True,
                'cert_info': {},
                'findings': [{
                    'category': 'SSL/TLS',
                    'level': 'HIGH',
                    'title': 'Invalid SSL Certificate (Untrusted / Self-Signed)',
                    'detail': f'SSL handshake failed verification: {str(e)}',
                    'remediation': 'Deploy a certificate issued by a trusted Certificate Authority (e.g. Let\'s Encrypt).'
                }]
            }
        except Exception as e:
            return {
                'enabled': True,
                'cert_info': {},
                'findings': [{
                    'category': 'SSL/TLS',
                    'level': 'LOW',
                    'title': 'SSL Audit Incomplete',
                    'detail': f'Could not complete deep TLS inspection: {str(e)}',
                    'remediation': 'Ensure port 443 is reachable.'
                }]
            }
