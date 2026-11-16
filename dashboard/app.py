"""
Interactive Security Dashboard (Streamlit)
Real-time visual monitoring, threat feed, and compliance audit explorer.
Course: CSET 462 - Cloud Security and Compliances
"""

import sys
import os
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT_DIR))

import streamlit as st
import pandas as pd
import json

from src.log_simulator import simulate_logs, simulate_demo_logs
from src.log_parser import LogParser
from src.threat_detector import ThreatDetector
from src.compliance_checker import ComplianceChecker
from src.reporter import SecurityReporter
from src.alerting import AlertManager

# Configure Streamlit page
st.set_page_config(
    page_title="Cloud Security Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for modern styling
st.markdown("""
<style>
    .metric-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 15px;
        text-align: center;
    }
    .badge-critical { color: #f87171; font-weight: bold; }
    .badge-high { color: #fb923c; font-weight: bold; }
    .badge-medium { color: #facc15; font-weight: bold; }
    .badge-low { color: #2dd4bf; font-weight: bold; }
</style>
""", unsafe_allow_html=True)


def load_or_generate_data(num_logs: int, inject_attacks: bool, dataset: str, uploaded_file=None):
    is_demo = dataset == "Focused demo (17 events)"
    log_file = ROOT_DIR / "logs" / ("demo_logs.json" if is_demo else "cloud_logs.json")
    parser = LogParser()

    if uploaded_file is not None:
        raw = json.load(uploaded_file)
        df = parser.parse_to_dataframe(raw)
    else:
        if not log_file.exists():
            if is_demo:
                simulate_demo_logs(output_file=str(log_file))
            else:
                simulate_logs(num_logs=num_logs, output_file=str(log_file), inject_attacks=inject_attacks)
        raw = parser.load_json(log_file)
        df = parser.parse_to_dataframe(raw)

    detector = ThreatDetector(df)
    incidents = detector.detect_all()

    compliance = ComplianceChecker(df)
    compliance_results = compliance.run_all_checks()

    summary = parser.get_summary_statistics()
    return df, incidents, compliance_results, summary


# Sidebar controls
st.sidebar.title("🛡️ Control Panel")
st.sidebar.markdown("**CSET 462:** Cloud Security & Compliances")
st.sidebar.markdown("**Team:** Shourya Tuhar, Manan Gupta, Mayank Sheoran, Mandeep Singh")
st.sidebar.divider()

st.sidebar.subheader("Simulation Settings")
dataset = st.sidebar.selectbox(
    "Dataset",
    ["Focused demo (17 events)", "Full simulation"],
    help="The focused dataset contains a small number of normal events and clear example attacks for a walkthrough."
)
if dataset == "Full simulation":
    log_count = st.sidebar.slider("Number of Logs to Generate", min_value=100, max_value=2000, value=300, step=50)
    attacks_toggle = st.sidebar.checkbox("Inject Multi-Vector Attack Scenarios", value=True)
else:
    log_count = 300
    attacks_toggle = True
    st.sidebar.caption("Compact walkthrough data with normal activity and six clear detections.")

if st.sidebar.button("🔄 Regenerate Simulated Logs", use_container_width=True):
    if dataset == "Focused demo (17 events)":
        log_file = ROOT_DIR / "logs" / "demo_logs.json"
        simulate_demo_logs(output_file=str(log_file))
    else:
        log_file = ROOT_DIR / "logs" / "cloud_logs.json"
        simulate_logs(num_logs=log_count, output_file=str(log_file), inject_attacks=attacks_toggle)
    st.sidebar.success("New logs generated successfully!")

st.sidebar.divider()
uploaded_file = st.sidebar.file_uploader("Upload External CloudTrail JSON", type=["json"])

# Load data
df, incidents, compliance_results, summary = load_or_generate_data(log_count, attacks_toggle, dataset, uploaded_file)
alert_manager = AlertManager(incidents)

# Main Application Header
st.title("🛡️ Python-Based Cloud Security Log Analyzer")
st.markdown("Automated Cloud Threat Detection, MITRE ATT&CK Mapping & CIS Benchmark Compliance Engine")
st.caption("Synthetic demonstration data only. CIS findings are inferred from sample events; no live AWS account is audited.")

# KPI Summary Cards
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
with kpi1:
    st.metric("Total Events", f"{summary.get('total_events', 0):,}")
with kpi2:
    crit_count = sum(1 for i in incidents if i["severity"] == "CRITICAL")
    st.metric("Critical Incidents", crit_count, delta="Immediate Action" if crit_count > 0 else "Clean", delta_color="inverse")
with kpi3:
    st.metric("Total Threats", len(incidents), delta=f"{len(incidents)} flagged", delta_color="inverse")
with kpi4:
    score = compliance_results.get("compliance_score_percent", 0)
    st.metric("CIS Compliance", f"{score}%", delta=compliance_results.get("compliance_rating", "Audited"))
with kpi5:
    failed_controls = compliance_results.get("failed_checks", 0)
    st.metric("Failed CIS Checks", f"{failed_controls} / {compliance_results.get('total_checks', 0)}")

st.divider()

# Navigation Tabs
tab_threats, tab_compliance, tab_analytics, tab_logs, tab_reports = st.tabs([
    "🚨 Threat Detection Feed",
    "⚖️ CIS Compliance Audit",
    "📈 Analytics & Visualizations",
    "🔍 Raw Log Explorer",
    "📄 Executive Reports"
])

with tab_threats:
    st.subheader("🚨 Detected Threats Mapped to MITRE ATT&CK Cloud Matrix")
    severity_counts = alert_manager.get_severity_breakdown()
    alert_cols = st.columns(4)
    for column, severity in zip(alert_cols, ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
        column.metric(f"{severity} alerts", severity_counts.get(severity, 0))
    siem_events = alert_manager.generate_siem_events()
    st.download_button(
        "Download AlertManager SIEM feed",
        data=json.dumps(siem_events, indent=2),
        file_name="siem_alert_feed.json",
        mime="application/json"
    )

    # Severity filter
    col_filter1, col_filter2 = st.columns([2, 4])
    with col_filter1:
        sev_filter = st.multiselect("Filter by Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM"])

    filtered_incidents = [i for i in incidents if i.get("severity") in sev_filter]

    if filtered_incidents:
        inc_df = pd.DataFrame([{
            "ID": i["incident_id"],
            "Severity": i["severity"],
            "Detection Rule": i["rule_name"],
            "MITRE Technique": i["mitre_technique"],
            "Actor User": i["actor_user"],
            "Source IP": i["actor_ip"],
            "Timestamp": i["timestamp"],
            "Description": i["description"]
        } for i in filtered_incidents])

        st.dataframe(inc_df, use_container_width=True, hide_index=True)

        st.markdown("#### Incident Deep-Dive Evidence")
        selected_id = st.selectbox("Select Incident ID for Evidence Dossier", [i["incident_id"] for i in filtered_incidents])
        match = next(i for i in filtered_incidents if i["incident_id"] == selected_id)
        st.json({
            "Incident ID": match["incident_id"],
            "Rule": match["rule_name"],
            "Confidence": f"{match['confidence']}%",
            "Actor": match["actor_user"],
            "IP Address": match["actor_ip"],
            "Resource": match["resource"],
            "Detailed Evidence": match["evidence"]
        })
    else:
        st.info("No incidents match the selected filter.")

with tab_compliance:
    st.subheader("⚖️ CIS AWS Foundations Benchmark v3.0 Compliance Scorecard")
    st.caption("These checks infer findings from the selected log dataset. A real CIS audit requires inspecting AWS configuration directly.")
    st.markdown(f"**Overall Compliance Score:** `{score}%` — **Rating:** `{compliance_results.get('compliance_rating')}`")

    checks = compliance_results.get("checks", [])
    for chk in checks:
        st_color = "🟢" if chk["status"] == "PASSED" else ("🟡" if chk["status"] == "WARNING" else "🔴")
        with st.expander(f"{st_color} [{chk['control_id']}] {chk['title']} - Status: {chk['status']}"):
            c1, c2 = st.columns([1, 1])
            with c1:
                st.markdown(f"**Benchmark Standard:** {chk['standard']}")
                st.markdown(f"**Severity Level:** `{chk['severity']}`")
                st.markdown(f"**Audit Finding:** {chk['details']}")
            with c2:
                st.markdown("#### 🔧 Remediation Instructions")
                st.info(chk["remediation"])

with tab_analytics:
    st.subheader("📈 Security Telemetry & Anomaly Analytics")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### Event Distribution by Cloud Service")
        svc_chart = df["eventSource"].value_counts()
        st.bar_chart(svc_chart)
    with c2:
        st.markdown("#### Event Status Distribution")
        stat_chart = df["status"].value_counts()
        st.bar_chart(stat_chart)

    st.markdown("#### Top Suspicious / Active Users")
    user_chart = df[df["is_failed"]]["userName"].value_counts().head(8)
    st.bar_chart(user_chart)

with tab_logs:
    st.subheader("🔍 Normalized Cloud Security Logs")
    search = st.text_input("Filter logs by user, action, IP, or service:")
    display_df = df.copy()
    if search:
        mask = (
            display_df["userName"].str.contains(search, case=False, na=False) |
            display_df["eventName"].str.contains(search, case=False, na=False) |
            display_df["ipAddress"].str.contains(search, case=False, na=False) |
            display_df["eventSource"].str.contains(search, case=False, na=False)
        )
        display_df = display_df[mask]

    st.dataframe(
        display_df[["eventTime", "eventSource", "eventName", "userName", "ipAddress", "awsRegion", "status", "bytesTransferred"]],
        use_container_width=True,
        hide_index=True
    )

with tab_reports:
    st.subheader("📄 Security Audit Report Generation")
    st.markdown("Generate and export comprehensive compliance & threat audit reports.")

    reporter = SecurityReporter(summary, incidents, compliance_results)
    html_path = reporter.export_html()
    json_path = reporter.export_json()
    md_path = reporter.export_markdown()

    r1, r2, r3 = st.columns(3)
    with r1:
        with open(html_path, "r", encoding="utf-8") as f:
            st.download_button(
                label="📥 Download HTML Audit Report",
                data=f.read(),
                file_name="security_compliance_report.html",
                mime="text/html",
                use_container_width=True
            )
    with r2:
        with open(json_path, "r", encoding="utf-8") as f:
            st.download_button(
                label="📥 Download SIEM JSON Report",
                data=f.read(),
                file_name="security_compliance_report.json",
                mime="application/json",
                use_container_width=True
            )
    with r3:
        with open(md_path, "r", encoding="utf-8") as f:
            st.download_button(
                label="📥 Download Markdown Summary",
                data=f.read(),
                file_name="security_audit_summary.md",
                mime="text/markdown",
                use_container_width=True
            )

    st.markdown("#### HTML Executive Report Preview")
    with open(html_path, "r", encoding="utf-8") as f:
        st.components.v1.html(f.read(), height=650, scrolling=True)
