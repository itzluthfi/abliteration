import requests
import random
import string
import time
import re

class TempMailClient:
    """Disposable Email Engine using Mail.tm API for Out-of-Band (OAST) and Registration Testing."""
    BASE_URL = "https://api.mail.tm"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Abliteration-OAST/3.3 (+https://github.com/itzluthfi/abliteration)'
        })
        self.email = None
        self.password = None
        self.token = None

    def get_domains(self):
        try:
            resp = self.session.get(f"{self.BASE_URL}/domains", timeout=10)
            if resp.status_code == 200:
                domains = resp.json().get('hydra:member', [])
                if domains:
                    return [d['domain'] for d in domains if d.get('isActive')]
        except Exception as e:
            print(f"[!] Error fetching domains: {e}")
        return ['mailtm.me']

    def create_inbox(self):
        """Generates a random disposable email address and authenticates."""
        domains = self.get_domains()
        domain = random.choice(domains)
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        self.email = f"ablit_{random_str}@{domain}"
        self.password = ''.join(random.choices(string.ascii_letters + string.digits + '!@#$', k=14))

        # Register
        payload = {"address": self.email, "password": self.password}
        reg_resp = self.session.post(f"{self.BASE_URL}/accounts", json=payload, timeout=10)
        if reg_resp.status_code not in [200, 201]:
            raise RuntimeError(f"Failed to register inbox: {reg_resp.text}")

        # Authenticate
        token_resp = self.session.post(f"{self.BASE_URL}/token", json=payload, timeout=10)
        if token_resp.status_code != 200:
            raise RuntimeError(f"Failed to obtain auth token: {token_resp.text}")

        self.token = token_resp.json().get('token')
        self.session.headers.update({'Authorization': f'Bearer {self.token}'})

        return self.email

    def fetch_messages(self):
        """Returns list of messages in inbox."""
        if not self.token:
            return []
        try:
            resp = self.session.get(f"{self.BASE_URL}/messages", timeout=10)
            if resp.status_code == 200:
                return resp.json().get('hydra:member', [])
        except Exception:
            pass
        return []

    def get_message_detail(self, message_id):
        """Fetches full text, HTML, and extracts OTPs and URLs."""
        try:
            resp = self.session.get(f"{self.BASE_URL}/messages/{message_id}", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                text = data.get('text', '')
                html = data.get('html', [''])[0] if isinstance(data.get('html'), list) else data.get('html', '')
                content = text or html

                # Extract potential OTP (4-8 digits)
                otp_match = re.search(r'\b\d{4,8}\b', content)
                otp = otp_match.group(0) if otp_match else None

                # Extract links
                urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)

                return {
                    'from': data.get('from', {}).get('address'),
                    'subject': data.get('subject'),
                    'snippet': data.get('intro'),
                    'otp': otp,
                    'urls': urls,
                    'raw_text': text
                }
        except Exception:
            pass
        return None

    def listen(self, duration_sec=120, interval=4):
        """Listens for incoming emails in real-time until timeout or message received."""
        print(f"\n[⚡] Listening for incoming emails on: {self.email}")
        print(f"    Waiting up to {duration_sec}s (Press Ctrl+C to abort)...\n")
        
        start = time.time()
        seen_ids = set()

        while time.time() - start < duration_sec:
            messages = self.fetch_messages()
            for msg in messages:
                m_id = msg['id']
                if m_id not in seen_ids:
                    seen_ids.add(m_id)
                    detail = self.get_message_detail(m_id)
                    if detail:
                        print("=" * 60)
                        print(f"📩 NEW EMAIL RECEIVED!")
                        print(f"From    : {detail['from']}")
                        print(f"Subject : {detail['subject']}")
                        if detail['otp']:
                            print(f"🔑 OTP Code Detected : \033[92m{detail['otp']}\033[0m")
                        if detail['urls']:
                            print(f"🔗 Links Found       : {detail['urls'][:2]}")
                        print(f"Snippet : {detail['snippet']}")
                        print("=" * 60)
            time.sleep(interval)

        print("\n[!] Listening window expired.")

if __name__ == '__main__':
    client = TempMailClient()
    email = client.create_inbox()
    print(f"Generated Disposable Email: {email}")
    client.listen(duration_sec=60)
