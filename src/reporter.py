"""
Security and Compliance Reporter Module
Compiles executive audit reports in HTML, JSON, and Markdown formats.
Course: CSET 462 - Cloud Security and Compliances
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List


class SecurityReporter:
    """
    Compiles analysis, threats, and compliance results into comprehensive executive reports.
    """

    def __init__(self, summary_stats: Dict[str, Any], incidents: List[Dict[str, Any]],
                 compliance_results: Dict[str, Any], output_dir: str = "reports"):
        self.summary = summary_stats
        self.incidents = incidents
        self.compliance = compliance_results
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def export_json(self, filename: str = "security_compliance_report.json") -> str:
        """Exports complete analysis to JSON."""
        data = {
            "meta": {
                "project": "Python-Based Cloud Security Log Analyzer",
                "course": "CSET 462 - Cloud Security and Compliances",
                "generated_at": self.report_time,
                "team": ["Shourya Tuhar (Leader)", "Manan Gupta", "Mayank Sheoran", "Mandeep Singh"]
            },
            "summary_statistics": self.summary,
            "threat_incidents": self.incidents,
            "compliance_audit": self.compliance
        }
        path = self.output_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return str(path)

    def export_markdown(self, filename: str = "security_audit_summary.md") -> str:
        """Exports an executive summary in GitHub Flavored Markdown."""
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for inc in self.incidents:
            s = inc.get("severity", "LOW")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        md = f"""# Cloud Security & Compliance Audit Report
**Course:** CSET 462 – Cloud Security and Compliances  
**Project:** Python-Based Cloud Security Log Analyzer  
**Team Members:** Shourya Tuhar (Leader), Manan Gupta, Mayank Sheoran, Mandeep Singh  
**Audit Timestamp:** {self.report_time}  

---

## Executive Summary
- **Total Cloud Events Analyzed:** {self.summary.get('total_events', 0):,}
- **Detected Security Incidents:** {len(self.incidents)}
  - **CRITICAL:** {sev_counts['CRITICAL']} | **HIGH:** {sev_counts['HIGH']} | **MEDIUM:** {sev_counts['MEDIUM']} | **LOW:** {sev_counts['LOW']}
- **CIS Benchmark Compliance Score:** **{self.compliance.get('compliance_score_percent', 0)}%** ({self.compliance.get('compliance_rating', 'N/A')})
- **Failed Compliance Controls:** {self.compliance.get('failed_checks', 0)} of {self.compliance.get('total_checks', 0)}

---

## 1. Threat Detection Findings (MITRE ATT&CK Mapped)
| Incident ID | Severity | Threat / Rule | MITRE Technique | Actor User | Source IP |
|---|---|---|---|---|---|
"""
        for inc in self.incidents:
            md += f"| `{inc['incident_id']}` | **{inc['severity']}** | {inc['rule_name']} | `{inc['mitre_technique']}` | `{inc['actor_user']}` | `{inc['actor_ip']}` |\n"

        md += f"""
---

## 2. CIS AWS Foundations Benchmark Audit
| Control ID | Benchmark Control | Status | Severity | Remediation Summary |
|---|---|---|---|---|
"""
        for chk in self.compliance.get("checks", []):
            status_badge = f"**{chk['status']}**" if chk['status'] == "PASSED" else f"❌ **{chk['status']}**"
            md += f"| `{chk['control_id']}` | {chk['title']} | {status_badge} | {chk['severity']} | {chk['remediation']} |\n"

        path = self.output_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            f.write(md)
        return str(path)

    def export_html(self, filename: str = "security_compliance_report.html") -> str:
        """Generates an executive, modern HTML audit report."""
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for inc in self.incidents:
            s = inc.get("severity", "LOW")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        score = self.compliance.get('compliance_score_percent', 0)
        score_color = "#2a9d8f" if score >= 85 else ("#f4a261" if score >= 60 else "#e63946")

        incident_rows = ""
        for inc in self.incidents:
            badge_class = inc['severity'].lower()
            incident_rows += f"""
            <tr>
                <td><code>{inc['incident_id']}</code></td>
                <td><span class="badge badge-{badge_class}">{inc['severity']}</span></td>
                <td><strong>{inc['rule_name']}</strong></td>
                <td><span class="mitre-tag">{inc['mitre_technique']}</span></td>
                <td><code>{inc['actor_user']}</code></td>
                <td><code>{inc['actor_ip']}</code></td>
                <td>{inc['description']}</td>
            </tr>
            """

        compliance_rows = ""
        for chk in self.compliance.get("checks", []):
            st = chk['status']
            st_class = "badge-success" if st == "PASSED" else ("badge-warning" if st == "WARNING" else "badge-danger")
            compliance_rows += f"""
            <tr>
                <td><code>{chk['control_id']}</code></td>
                <td><strong>{chk['title']}</strong></td>
                <td><span class="badge {st_class}">{st}</span></td>
                <td>{chk['severity']}</td>
                <td>{chk['details']}</td>
                <td class="remediation">{chk['remediation']}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Security & Compliance Executive Report - CSET 462</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #facc15;
            --low: #2dd4bf;
            --border: #334155;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border);
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 25px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        .header h1 {{ font-size: 24px; color: #fff; margin-bottom: 6px; }}
        .header .meta {{ color: var(--text-secondary); font-size: 14px; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }}
        .card .title {{ font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin-bottom: 8px; }}
        .card .value {{ font-size: 28px; font-weight: 700; color: #fff; }}
        .card .sub {{ font-size: 12px; color: var(--text-secondary); margin-top: 5px; }}
        .section-title {{ font-size: 20px; margin: 30px 0 15px; border-bottom: 2px solid var(--border); padding-bottom: 8px; display: flex; align-items: center; justify-content: space-between; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 30px;
            border: 1px solid var(--border);
        }}
        th, td {{ padding: 12px 14px; text-align: left; font-size: 13px; border-bottom: 1px solid var(--border); }}
        th {{ background-color: #162032; color: #cbd5e1; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }}
        tr:hover {{ background-color: rgba(255,255,255,0.02); }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; color: #38bdf8; }}
        .badge {{
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            display: inline-block;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }}
        .badge-medium {{ background: rgba(250, 204, 21, 0.2); color: #fde047; border: 1px solid #facc15; }}
        .badge-low {{ background: rgba(45, 212, 191, 0.2); color: #5eead4; border: 1px solid #2dd4bf; }}
        .badge-success {{ background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e; }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
        .badge-warning {{ background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid #eab308; }}
        .mitre-tag {{ font-family: monospace; font-size: 11px; background: #312e81; color: #c7d2fe; padding: 2px 6px; border-radius: 4px; }}
        .remediation {{ color: #cbd5e1; font-size: 12px; line-height: 1.4; }}
        .footer {{ text-align: center; color: var(--text-secondary); font-size: 12px; margin-top: 40px; border-top: 1px solid var(--border); padding-top: 15px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Python-Based Cloud Security Log Analyzer</h1>
            <div class="meta">
                <strong>Course:</strong> CSET 462 – Cloud Security and Compliances |
                <strong>Team:</strong> Shourya Tuhar (Leader), Manan Gupta, Mayank Sheoran, Mandeep Singh |
                <strong>Generated:</strong> {self.report_time}
            </div>
        </div>

        <div class="stats-grid">
            <div class="card">
                <div class="title">Total Events Audited</div>
                <div class="value">{self.summary.get('total_events', 0):,}</div>
                <div class="sub">{self.summary.get('unique_users', 0)} users | {self.summary.get('unique_ips', 0)} source IPs</div>
            </div>
            <div class="card">
                <div class="title">Threat Incidents</div>
                <div class="value" style="color: #f87171;">{len(self.incidents)}</div>
                <div class="sub">Critical: {sev_counts['CRITICAL']} | High: {sev_counts['HIGH']}</div>
            </div>
            <div class="card">
                <div class="title">CIS Compliance Score</div>
                <div class="value" style="color: {score_color};">{score}%</div>
                <div class="sub">{self.compliance.get('compliance_rating', 'Audited')}</div>
            </div>
            <div class="card">
                <div class="title">Failed Controls</div>
                <div class="value" style="color: #f97316;">{self.compliance.get('failed_checks', 0)} / {self.compliance.get('total_checks', 0)}</div>
                <div class="sub">Remediation required</div>
            </div>
        </div>

        <h2 class="section-title">🚨 Threat Detection Incidents (MITRE ATT&CK Cloud Matrix)</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Severity</th>
                    <th>Detection Rule</th>
                    <th>MITRE Technique</th>
                    <th>Target User</th>
                    <th>Source IP</th>
                    <th>Incident Details</th>
                </tr>
            </thead>
            <tbody>
                {incident_rows}
            </tbody>
        </table>

        <h2 class="section-title">🛡️ CIS AWS Foundations Benchmark v3.0 Compliance Audit</h2>
        <table>
            <thead>
                <tr>
                    <th>Control</th>
                    <th>Audit Title</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Findings</th>
                    <th>Recommended Remediation</th>
                </tr>
            </thead>
            <tbody>
                {compliance_rows}
            </tbody>
        </table>

        <div class="footer">
            Python-Based Cloud Security Log Analyzer • CSET 462 Capstone Project • Team: Shourya Tuhar, Manan Gupta, Mayank Sheoran, Mandeep Singh
        </div>
    </div>
</body>
</html>
        """
        path = self.output_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return str(path)
