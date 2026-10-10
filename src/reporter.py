import os
import json
from datetime import datetime

class Reporter:
    """Generates executive terminal, JSON, and professional visual HTML security audit reports with Proof of Concept (PoC)."""
    def __init__(self, target_url, findings, crawl_stats, ssl_data=None, waf_name="Undetected", score=100, grade="A", output_dir="OUTPUT"):
        self.target_url = target_url
        self.findings = findings
        self.crawl_stats = crawl_stats
        self.ssl_data = ssl_data or {}
        self.waf_name = waf_name
        self.score = score
        self.grade = grade
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def print_terminal_summary(self):
        high = sum(1 for f in self.findings if f['level'] == 'HIGH')
        med = sum(1 for f in self.findings if f['level'] == 'MEDIUM')
        low = sum(1 for f in self.findings if f['level'] == 'LOW')
        info = sum(1 for f in self.findings if f['level'] == 'INFO')

        grade_color = '\033[92m' if self.grade in ['A+', 'A'] else '\033[93m' if self.grade in ['B', 'C'] else '\033[91m'
        reset = '\033[0m'
        bold = '\033[1m'
        cyan = '\033[96m'

        print("\n" + "=" * 70)
        print("          🛡️  ABLITERATION v3.3 - EVIDENCE-BACKED SECURITY AUDIT")
        print("=" * 70)
        print(f"Target URL     : {self.target_url}")
        print(f"Security Grade : {grade_color}{bold}[ GRADE: {self.grade} ] ({self.score}/100){reset}")
        print(f"WAF / Perimeter: {bold}{self.waf_name}{reset}")
        
        cert = self.ssl_data.get('cert_info', {})
        if cert:
            print(f"SSL/TLS Status : {cert.get('tls_version', 'HTTPS')} | Issuer: {cert.get('issuer', 'N/A')} ({cert.get('days_left', '?')} days left)")
        
        print(f"Pages Crawled  : {self.crawl_stats.get('visited_count', 0)}")
        print(f"Forms Found    : {len(self.crawl_stats.get('forms', []))}")
        print(f"Params Tested  : {len(self.crawl_stats.get('params', []))}")
        print("-" * 70)
        print(f"Risk Matrix    : [🔴 HIGH: {high}]  [🟡 MEDIUM: {med}]  [🔵 LOW: {low}]  [⚪ INFO: {info}]")
        print("=" * 70)

        if not self.findings:
            print(f"\n  {grade_color}[✓] Excellent! No security risks identified across all test suites.{reset}")
        else:
            for i, f in enumerate(self.findings, 1):
                lvl = f['level']
                prefix = "🔴" if lvl == 'HIGH' else "🟡" if lvl == 'MEDIUM' else "🔵" if lvl == 'LOW' else "⚪"
                print(f"\n{i}. {prefix} [{lvl}] {f['title']} ({f['category']})")
                print(f"   Detail     : {f['detail']}")
                if f.get('poc_curl'):
                    print(f"   {cyan}PoC (curl) : {f['poc_curl']}{reset}")
                if f.get('evidence_snippet'):
                    print(f"   Evidence   : {f['evidence_snippet']}")
                if f.get('remediation'):
                    print(f"   Fix        : {f['remediation']}")

        print("\n" + "=" * 70)

    def export_json(self, filename="audit_report.json"):
        path = os.path.join(self.output_dir, filename)
        data = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'grade': self.grade,
            'score': self.score,
            'waf_perimeter': self.waf_name,
            'ssl_info': self.ssl_data,
            'crawl_stats': self.crawl_stats,
            'summary': {
                'high': sum(1 for f in self.findings if f['level'] == 'HIGH'),
                'medium': sum(1 for f in self.findings if f['level'] == 'MEDIUM'),
                'low': sum(1 for f in self.findings if f['level'] == 'LOW'),
                'info': sum(1 for f in self.findings if f['level'] == 'INFO'),
            },
            'findings': self.findings
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return path

    def export_html(self, filename="audit_report.html"):
        path = os.path.join(self.output_dir, filename)
        high = sum(1 for f in self.findings if f['level'] == 'HIGH')
        med = sum(1 for f in self.findings if f['level'] == 'MEDIUM')
        low = sum(1 for f in self.findings if f['level'] == 'LOW')
        info = sum(1 for f in self.findings if f['level'] == 'INFO')

        grade_bg = "#10b981" if self.grade in ['A+', 'A'] else "#f59e0b" if self.grade in ['B', 'C'] else "#ef4444"

        cert = self.ssl_data.get('cert_info', {})
        ssl_html = ""
        if cert:
            ssl_html = f"""
            <div style="background:#0f172a; padding:12px; border-radius:6px; margin-top:12px; display:flex; justify-content:space-between; font-size:13px; color:#cbd5e1;">
                <div>🔒 <strong>Protocol:</strong> {cert.get('tls_version', 'TLS')} ({cert.get('cipher', 'N/A')})</div>
                <div>🏢 <strong>Issuer:</strong> {cert.get('issuer', 'N/A')}</div>
                <div>⏳ <strong>Validity:</strong> {cert.get('days_left', '?')} days left (Expires {cert.get('expires_at', 'N/A')})</div>
            </div>
            """

        items_html = ""
        for f in self.findings:
            color = "#ef4444" if f['level'] == 'HIGH' else "#f59e0b" if f['level'] == 'MEDIUM' else "#3b82f6" if f['level'] == 'LOW' else "#6b7280"
            poc_block = ""
            if f.get('poc_curl'):
                poc_block = f"""
                <div style="margin-top:10px;">
                    <div style="font-size:11px; font-weight:bold; color:#38bdf8; margin-bottom:4px;">REPRODUCIBLE PROOF OF CONCEPT (PoC / CURL):</div>
                    <div style="background:#0f172a; border:1px solid #334155; padding:8px 12px; border-radius:4px; font-family:monospace; font-size:12px; color:#e2e8f0; overflow-x:auto;">{f['poc_curl']}</div>
                </div>
                """
            evidence_block = ""
            if f.get('evidence_snippet'):
                evidence_block = f"""
                <div style="margin-top:6px; font-size:12px; color:#94a3b8;">
                    <strong>Evidence:</strong> <code>{f['evidence_snippet']}</code>
                </div>
                """

            items_html += f"""
            <div style="background:#1e293b; border-left:4px solid {color}; padding:18px; margin-bottom:14px; border-radius:6px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <h3 style="margin:0; color:#f8fafc; font-size:16px;">{f['title']}</h3>
                    <span style="background:{color}; color:#fff; padding:3px 8px; border-radius:4px; font-size:12px; font-weight:bold;">{f['level']}</span>
                </div>
                <p style="color:#94a3b8; font-size:13px; margin:6px 0;"><strong>Category:</strong> {f['category']}</p>
                <p style="color:#cbd5e1; font-size:14px; margin:6px 0;">{f['detail']}</p>
                {evidence_block}
                {poc_block}
                {f'<div style="background:#0f172a; padding:10px; border-radius:4px; margin-top:10px; font-family:monospace; color:#4ade80; font-size:12px;"><strong>Remediation:</strong> {f["remediation"]}</div>' if f.get('remediation') else ''}
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Abliteration v3.3 Evidence-Backed Security Audit - {self.target_url}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
        .container {{ max-width: 940px; margin: 0 auto; }}
        .header {{ background: #1e293b; padding: 24px; border-radius: 8px; margin-bottom: 24px; }}
        .top-banner {{ display:flex; justify-content:space-between; align-items:center; }}
        .grade-badge {{ background: {grade_bg}; color:#fff; font-size:28px; font-weight:bold; padding:8px 20px; border-radius:8px; text-align:center; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 16px; }}
        .card {{ background: #0f172a; padding: 12px; border-radius: 6px; text-align: center; }}
        .num {{ font-size: 24px; font-weight: bold; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="top-banner">
                <div>
                    <h1 style="margin:0; font-size:24px;">🛡️ Abliteration v3.3 Security Audit Report</h1>
                    <p style="color:#94a3b8; margin:6px 0 0 0;">Target: <a href="{self.target_url}" style="color:#38bdf8;" target="_blank">{self.target_url}</a> | Perimeter: <span style="color:#38bdf8; font-weight:bold;">{self.waf_name}</span> | Audited: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                <div class="grade-badge">
                    <div style="font-size:12px; letter-spacing:1px; opacity:0.8;">SECURITY GRADE</div>
                    {self.grade} <span style="font-size:16px; font-weight:normal;">({self.score}/100)</span>
                </div>
            </div>
            {ssl_html}
            <div class="stats">
                <div class="card"><div style="color:#94a3b8; font-size:12px;">PAGES CRAWLED</div><div class="num" style="color:#38bdf8;">{self.crawl_stats.get('visited_count', 0)}</div></div>
                <div class="card"><div style="color:#94a3b8; font-size:12px;">HIGH RISKS</div><div class="num" style="color:#ef4444;">{high}</div></div>
                <div class="card"><div style="color:#94a3b8; font-size:12px;">MEDIUM RISKS</div><div class="num" style="color:#f59e0b;">{med}</div></div>
                <div class="card"><div style="color:#94a3b8; font-size:12px;">LOW RISKS</div><div class="num" style="color:#3b82f6;">{low}</div></div>
            </div>
        </div>
        <h2 style="font-size:20px; border-bottom:1px solid #334155; padding-bottom:8px;">Verifiable Findings & Proof of Concept (PoC)</h2>
        {items_html if items_html else '<p style="color:#10b981;">No security findings identified. All baseline security controls passed.</p>'}
    </div>
</body>
</html>"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return path
