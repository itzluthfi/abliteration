import urllib.parse
from bs4 import BeautifulSoup
import requests

class Crawler:
    """Smart Web Spider to discover internal endpoints, forms, and parameters."""
    def __init__(self, base_url, max_pages=15, timeout=8):
        self.base_url = base_url.rstrip('/')
        self.domain = urllib.parse.urlparse(self.base_url).netloc
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited = set()
        self.endpoints = set([self.base_url])
        self.forms = []       # [{'action': str, 'method': str, 'inputs': [str]}]
        self.params = set()    # list of unique query parameter names
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Abliteration-Auditor/3.0 (+https://github.com/itzluthfi/abliteration)'
        })

    def is_internal(self, url):
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc == '' or parsed.netloc == self.domain

    def crawl(self):
        queue = [self.base_url]

        while queue and len(self.visited) < self.max_pages:
            current = queue.pop(0)
            if current in self.visited:
                continue

            self.visited.add(current)
            try:
                resp = self.session.get(current, timeout=self.timeout, allow_redirects=True)
            except Exception:
                continue

            # Only parse HTML responses
            content_type = resp.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                continue

            soup = BeautifulSoup(resp.text, 'html.parser')

            # 1. Extract Links
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                if href.startswith('#') or href.startswith('javascript:'):
                    continue
                full_url = urllib.parse.urljoin(current, href)
                if self.is_internal(full_url):
                    # Strip fragment
                    full_url = full_url.split('#')[0]
                    # Collect query parameters
                    parsed_q = urllib.parse.urlparse(full_url)
                    if parsed_q.query:
                        for p in urllib.parse.parse_qs(parsed_q.query):
                            self.params.add(p)
                    self.endpoints.add(full_url)
                    if full_url not in self.visited and full_url not in queue:
                        queue.append(full_url)

            # 2. Extract Forms & Inputs
            for form in soup.find_all('form'):
                action = form.get('action') or current
                method = (form.get('method') or 'GET').upper()
                full_action = urllib.parse.urljoin(current, action)
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if name:
                        inputs.append(name)
                        self.params.add(name)
                self.forms.append({
                    'action': full_action,
                    'method': method,
                    'inputs': inputs
                })

        return {
            'visited_count': len(self.visited),
            'endpoints': list(self.endpoints),
            'forms': self.forms,
            'params': list(self.params)
        }
