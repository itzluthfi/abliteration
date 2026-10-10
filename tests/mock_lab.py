#!/usr/bin/env python3
import http.server
import socketserver
import urllib.parse
import sys

PORT = 8888

class MockVulnerableHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Quiet logging

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Real Exposed Sensitive File
        if path == '/.env':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"APP_ENV=production\nDB_CONNECTION=mysql\nDB_PASSWORD=SuperSecretPass123!\nAPI_KEY=live_sk_991823\n")
            return

        # 2. Real Exposed Swagger API Doc
        if path == '/swagger.json':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"swagger":"2.0","info":{"title":"Internal Mock API","version":"1.0"},"paths":{"/api/users":{"get":{"description":"List users"}}}}')
            return

        # 3. Real Reflected Parameter (XSS vulnerability)
        if path == '/search':
            q = query.get('q', [''])[0]
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            # Vulnerable: Reflects unescaped q directly
            html = f"<html><body><h1>Search Results for: {q}</h1><p>0 results found.</p><a href='/'>Back Home</a></body></html>"
            self.wfile.write(html.encode('utf-8'))
            return

        # 4. Default Home Page with forms and links (Missing Security Headers)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        # Deliberately insecure cookie (Missing HttpOnly and Secure)
        self.send_header('Set-Cookie', 'session_token=xyz12345; Path=/')
        self.end_headers()

        html = """<!DOCTYPE html>
<html>
<head><title>Mock Vulnerable Security Lab</title></head>
<body>
    <h1>Local Security Test Target</h1>
    <p>This mock server contains intentionally configured security flaws to verify Abliteration's detection engine.</p>
    <ul>
        <li><a href="/search?q=test">Search Portal</a></li>
        <li><a href="/swagger.json">API Definition</a></li>
        <li><a href="/.env">Configuration File</a></li>
    </ul>
    <form action="/search" method="GET">
        <label>Query: <input type="text" name="q" value="laptop"></label>
        <button type="submit">Search</button>
    </form>
</body>
</html>"""
        self.wfile.write(html.encode('utf-8'))

def run_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), MockVulnerableHandler) as httpd:
        print(f"[*] Mock Vulnerable Test Lab running at: http://127.0.0.1:{PORT}")
        print("    Press Ctrl+C to terminate.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down lab.")

if __name__ == '__main__':
    run_server()
