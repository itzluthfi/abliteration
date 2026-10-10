import os
import json
from datetime import datetime

class Reporter:
    """Generates terminal, JSON, and clean HTML security audit reports."""
    def __init__(self, target_url, findings, crawl_stats, output_dir="OUTPUT"):
        self.target_url = target_url
        self.findings = findings
        self.crawl_stats = crawl_stats
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def print_terminal_summary(self):
        high = sum(1 for f in self.findings if f['level'] == 'HIGH')
        med = sum(1 for f in self.findings if f['level'] == 'MEDIUM')
        low = sum(1 for f in self.findings if f['level'] == 'LOW')
        info = sum(1 for f in self.findings if f['level'] == 'INFO')

        print("\n" + "=" * 65)
        print("          🛡️  ABLITERATION v3.0 - EXECUTIVE AUDIT SUMMARY")
        print("=" * 65)
        print(f"Target URL     : {self.target_url}")
        print(f"Pages Crawled  : {self.crawl_stats.get('visited_count', 0)}")
        print(f"Forms Found    : {len(self.crawl_stats.get('forms', []))}")
        print(f"Params Tested  : {len(self.crawl_stats.get('params', []))}")
        print("-" * 65)
        print(f"Risk Breakdown : [🔴 HIGH: {high}]  [🟡 MEDIUM: {med}]  [🔵 LOW: {low}]  [⚪ INFO: {info}]")
        print("=" * 65)

        if not self.findings:
            print("\n  [✓] No significant vulnerabilities or missing security controls detected!")
        else:
            for i, f in enumerate(self.findings, 1):
                lvl = f['level']
                prefix = "🔴" if lvl == 'HIGH' else "🟡" if lvl == 'MEDIUM' else "🔵" if lvl == 'LOW' else "⚪"
                print(f"\n{i}. {prefix} [{lvl}] {f['title']} ({f['category']})")
                print(f"   Detail     : {f['detail']}")
                if f.get('remediation'):
                    print(f"   Remediation: {f['remediation']}")

        print("\n" + "=" * 65)

    def export_json(self, filename="audit_report.json"):
        path = os.path.join(self.output_dir, filename)
        data = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
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

        items_html = ""
        for f in self.findings:
            color = "#ef4444" if f['level'] == 'HIGH' else "#f59e0b" if f['level'] == 'MEDIUM' else "#3b82f6" if f['level'] == 'LOW' else "#6b7280"
            items_html += f"""
            <div style="background:#1e293b; border-left:4px solid {color}; padding:16px; margin-bottom:12px; border-radius:6px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <h3 style="margin:0; color:#f8fafc; font-size:16px;">{f['title']}</h3>
                    <span style="background:{color}; color:#fff; padding:3px 8px; border-radius:4px; font-size:12px; font-weight:bold;">{f['level']}</span>
                </div>
                <p style="color:#94a3b8; font-size:14px; margin:8px 0;"><strong>Category:</strong> {f['category']}</p>
                <p style="color:#cbd5e1; font-size:14px; margin:8px 0;">{f['detail']}</p>
                {f'<div style="background:#0f172a; padding:10px; border-radius:4px; margin-top:8px; font-family:monospace; color:#38bdf8; font-size:13px;"><strong>Fix:</strong> {f["remediation"]}</div>' if f.get('remediation') else ''}
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Abliteration Security Audit - {self.target_url}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{ background: #1e293b; padding: 24px; border-radius: 8px; margin-bottom: 24px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 16px; }}
        .card {{ background: #0f172a; padding: 12px; border-radius: 6px; text-align: center; }}
        .num {{ font-size: 24px; font-weight: bold; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="margin:0; font-size:24px;">🛡️ Abliteration v3.0 Security Audit Report</h1>
            <p style="color:#94a3b8; margin:8px 0 0 0;">Target: <a href="{self.target_url}" style="color:#38bdf8;" target="_blank">{self.target_url}</a> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <div class="stats">
                <div class="card"><div style="color:#94a3b8; font-size:12px;">PAGES CRAWLED</div><div class="num" style="color:#38bdf8;">{self.crawl_stats.get('visited_count', 0)}</div></div>
                <div class="card"><div style="color:#94a3b8; font-size:12px;">HIGH RISKS</div><div class="num" style="color:#ef4444;">{high}</div></div>
                <div class="card"><div style="color:#94a3b8; font-size:12px;">MEDIUM RISKS</div><div class="num" style="color:#f59e0b;">{med}</div></div>
                <div class="card"><div style="color:#94a3b8; font-size:12px;">LOW RISKS</div><div class="num" style="color:#3b82f6;">{low}</div></div>
            </div>
        </div>
        <h2 style="font-size:20px; border-bottom:1px solid #334155; padding-bottom:8px;">Audit Findings & Recommendations</h2>
        {items_html if items_html else '<p style="color:#10b981;">No security findings identified. All evaluated baseline checks passed.</p>'}
    </div>
</body>
</html>"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return path
