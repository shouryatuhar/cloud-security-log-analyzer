# Running the Cloud Security Log Analyzer

This guide reproduces the focused demonstration used in the Milestone 4 walkthrough. The project uses synthetic cloud events; it does not connect to AWS or require cloud credentials.

## Requirements

- Python 3.10 or newer
- A terminal in the project folder
- Internet access for the initial package installation

## 1. Install dependencies

From the project folder, create and activate a virtual environment, then install the packages:

```bash
python -m venv .venv
source .venv/bin/activate        # macOS/Linux
# .venv\Scripts\activate        # Windows PowerShell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 2. Run the focused demonstration pipeline

```bash
python main.py --demo
```

This generates `logs/demo_logs.json`, parses the records, runs the threat detections and CIS indicator checks, routes detections through `AlertManager`, creates charts, and exports reports. The focused dataset contains 17 synthetic events and is designed to produce six understandable detections (four critical and two high).

Generated outputs:

- `reports/security_compliance_report.html` — executive report
- `reports/security_compliance_report.json` — complete analysis results
- `reports/security_audit_summary.md` — Markdown summary
- `reports/siem_alert_feed.json` — SIEM-formatted alert events
- `reports/charts/` — generated visualizations

## 3. Launch the interactive dashboard

```bash
python main.py --dashboard
```

Open the localhost URL printed in the terminal (normally `http://localhost:8501`). The dashboard defaults to **Focused demo (17 events)**. Its tabs let you explore:

1. **Threat Detection Feed:** severity counts, incident evidence, and a downloadable SIEM JSON feed.
2. **CIS Compliance Audit:** sample-log findings and remediation suggestions.
3. **Analytics & Visualizations:** event distributions and activity summaries.
4. **Raw Log Explorer:** searchable normalized events; try `StopLogging`.
5. **Executive Reports:** report preview and download options.

To use a larger generated dataset, choose **Full simulation** in the left sidebar. The number-of-logs slider appears for that mode. Select the focused demo again for results matching the walkthrough.

## Data and result notes

- All provided demo records are synthetic CloudTrail-style data. They do not represent events collected from an AWS account.
- CIS findings are inferred from the event sample. They are not a live assessment of AWS configuration.
- The default focused dataset is intended for a repeatable walkthrough; the full simulation includes random background activity and can produce more alerts.
- The dashboard requires the Python dependencies above. Keep the terminal running while using the localhost page; press `Ctrl+C` in that terminal to stop Streamlit.
