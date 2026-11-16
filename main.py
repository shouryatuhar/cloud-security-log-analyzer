"""
Main CLI Application Entrypoint
Python-Based Cloud Security Log Analyzer
Course: CSET 462 - Cloud Security and Compliances
Team: Shourya Tuhar (Leader), Manan Gupta, Mayank Sheoran, Mandeep Singh
"""

import argparse
import sys
import os
import subprocess
import json
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent
sys.path.append(str(ROOT_DIR))

from src.log_simulator import simulate_logs, simulate_demo_logs
from src.log_parser import LogParser
from src.threat_detector import ThreatDetector
from src.compliance_checker import ComplianceChecker
from src.alerting import AlertManager
from src.visualizer import SecurityVisualizer
from src.reporter import SecurityReporter

if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False


def print_banner():
    banner = """
================================================================================
          PYTHON-BASED CLOUD SECURITY LOG ANALYZER & SIEM ENGINE
   Course: CSET 462 - Cloud Security & Compliances (Milestones 1 - 5)
   Team: Shourya Tuhar (Leader), Manan Gupta, Mayank Sheoran, Mandeep Singh
================================================================================
    """
    if RICH_AVAILABLE:
        console.print(Panel(
            "[bold cyan]Python-Based Cloud Security Log Analyzer & SIEM Engine[/bold cyan]\n"
            "[green]Course: CSET 462 - Cloud Security and Compliances[/green]\n"
            "[yellow]Team: Shourya Tuhar (Leader), Manan Gupta, Mayank Sheoran, Mandeep Singh[/yellow]",
            border_style="bright_blue"
        ))
    else:
        print(banner)


def run_pipeline(num_logs: int = 300, log_path: str = "logs/cloud_logs.json",
                 generate_new: bool = True, seed: int = 42, demo: bool = False):
    """Executes the full cloud security detection and compliance pipeline."""
    print_banner()

    log_file = Path(log_path)

    # 1. Simulate or load logs
    if generate_new or not log_file.exists():
        if demo:
            print("\n[*] Generating a focused walkthrough dataset...")
            simulate_demo_logs(output_file=str(log_file), seed=seed)
        else:
            print(f"\n[*] Generating {num_logs} simulated cloud logs with cyber attack scenarios...")
            simulate_logs(num_logs=num_logs, output_file=str(log_file), seed=seed, inject_attacks=True)

    # 2. Ingest and parse logs
    print(f"\n[*] Ingesting and normalizing logs from: {log_file}")
    parser = LogParser(log_file)
    parser.load_json()
    df = parser.parse_to_dataframe()
    stats = parser.get_summary_statistics()

    if RICH_AVAILABLE:
        stats_table = Table(title="[bold green]Ingestion & Operational Summary[/bold green]")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="bold white")
        stats_table.add_row("Total Records", f"{stats['total_events']:,}")
        stats_table.add_row("Unique Users", f"{stats['unique_users']}")
        stats_table.add_row("Unique IPs", f"{stats['unique_ips']}")
        stats_table.add_row("Successful Operations", f"{stats['success_count']}")
        stats_table.add_row("Failed Operations", f"{stats['failed_count']}")
        stats_table.add_row("Unauthorized Operations", f"{stats['unauthorized_count']}")
        stats_table.add_row("Root Account Events", f"{stats['root_events_count']}")
        stats_table.add_row("Observation Window", f"{stats['date_range_start']} to {stats['date_range_end']}")
        console.print(stats_table)
    else:
        print("\n--- Operational Summary ---")
        for k, v in stats.items():
            if not isinstance(v, dict):
                print(f"  {k:25}: {v}")

    # 3. Threat Detection Engine
    print("\n[*] Executing Multi-Vector Threat Detection Engine (MITRE ATT&CK Cloud Matrix)...")
    detector = ThreatDetector(df)
    incidents = detector.detect_all()

    # 3a. Route each incident through the SIEM alert adapter. This keeps the
    # detection output usable by downstream systems as well as the dashboard.
    alert_manager = AlertManager(incidents)
    print("\n[*] Routing detections through the SIEM alerting module...")
    print(alert_manager.format_terminal_alerts(max_display=5))

    if RICH_AVAILABLE:
        threat_table = Table(title="[bold red][!] Detected Cloud Security Incidents (MITRE ATT&CK)[/bold red]")
        threat_table.add_column("ID", style="cyan", width=10)
        threat_table.add_column("Severity", style="bold red", width=10)
        threat_table.add_column("Detection Rule", style="white")
        threat_table.add_column("MITRE Technique", style="magenta")
        threat_table.add_column("Actor / IP", style="yellow")
        threat_table.add_column("Confidence", style="green", width=10)

        for inc in incidents:
            sev_color = "red" if inc["severity"] == "CRITICAL" else ("yellow" if inc["severity"] == "HIGH" else "cyan")
            threat_table.add_row(
                inc["incident_id"],
                f"[{sev_color}]{inc['severity']}[/{sev_color}]",
                inc["rule_name"],
                inc["mitre_technique"],
                f"{inc['actor_user']} ({inc['actor_ip']})",
                f"{inc['confidence']}%"
            )
        console.print(threat_table)
    else:
        print(f"\n--- Detected {len(incidents)} Incidents ---")
        for inc in incidents:
            print(f"  [{inc['severity']}] {inc['incident_id']} - {inc['rule_name']} | MITRE: {inc['mitre_technique']} | Actor: {inc['actor_user']}")

    # 4. Compliance Auditing Engine
    print("\n[*] Auditing against CIS AWS Foundations Benchmark v3.0...")
    compliance_checker = ComplianceChecker(df)
    comp_results = compliance_checker.run_all_checks()

    if RICH_AVAILABLE:
        comp_table = Table(title=f"[bold blue]CIS AWS Benchmark Compliance Scorecard ({comp_results['compliance_score_percent']}%) - {comp_results['compliance_rating']}[/bold blue]")
        comp_table.add_column("Control ID", style="cyan", width=10)
        comp_table.add_column("Title", style="white")
        comp_table.add_column("Status", style="bold", width=10)
        comp_table.add_column("Severity", style="yellow", width=10)
        comp_table.add_column("Remediation", style="green")

        for chk in comp_results["checks"]:
            st_color = "green" if chk["status"] == "PASSED" else ("red" if chk["status"] == "FAILED" else "yellow")
            comp_table.add_row(
                chk["control_id"],
                chk["title"],
                f"[{st_color}]{chk['status']}[/{st_color}]",
                chk["severity"],
                chk["remediation"]
            )
        console.print(comp_table)
    else:
        print(f"\n--- CIS Benchmark Compliance Score: {comp_results['compliance_score_percent']}% ---")
        for chk in comp_results["checks"]:
            print(f"  [{chk['status']:7}] {chk['control_id']}: {chk['title']}")

    # 5. Visualizations
    print("\n[*] Generating high-resolution security analytics charts...")
    visualizer = SecurityVisualizer(df, incidents, output_dir="reports/charts")
    charts = visualizer.generate_all_charts()
    for name, p in charts.items():
        print(f"  [+] Saved chart: {p}")

    # 6. Executive Reports
    print("\n[*] Compiling Executive Audit Reports (HTML, JSON, Markdown)...")
    reporter = SecurityReporter(stats, incidents, comp_results, output_dir="reports")
    html_file = reporter.export_html("security_compliance_report.html")
    json_file = reporter.export_json("security_compliance_report.json")
    md_file = reporter.export_markdown("security_audit_summary.md")
    siem_file = Path("reports/siem_alert_feed.json")
    siem_file.parent.mkdir(parents=True, exist_ok=True)
    with siem_file.open("w", encoding="utf-8") as f:
        json.dump(alert_manager.generate_siem_events(), f, indent=2)

    print(f"  [+] HTML Executive Report : {html_file}")
    print(f"  [+] SIEM JSON Report      : {json_file}")
    print(f"  [+] Markdown Summary      : {md_file}")
    print(f"  [+] SIEM Alert Feed       : {siem_file}")

    print("\n================================================================================")
    print("SUCCESS: End-to-end security log analysis and compliance audit completed!")
    print(f"Open '{html_file}' in your web browser to view the interactive audit report.")
    print("Run 'python main.py --dashboard' to launch the interactive live GUI dashboard.")
    print("================================================================================\n")


def launch_dashboard():
    """Launches the Streamlit interactive dashboard."""
    print("[*] Launching Streamlit Security Dashboard...")
    app_path = ROOT_DIR / "dashboard" / "app.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(app_path)]
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[*] Dashboard stopped.")


def main():
    parser = argparse.ArgumentParser(
        description="Python-Based Cloud Security Log Analyzer & Compliance Engine (CSET 462)"
    )
    parser.add_argument("--all", action="store_true", help="Run complete pipeline (Simulation -> Detection -> Compliance -> Charts -> Report)")
    parser.add_argument("--simulate", action="store_true", help="Generate simulated cloud logs only")
    parser.add_argument("--num-logs", type=int, default=300, help="Number of simulated records to generate")
    parser.add_argument("--file", type=str, default="logs/cloud_logs.json", help="Path to input cloud logs JSON")
    parser.add_argument("--dashboard", action="store_true", help="Launch interactive Streamlit dashboard")
    parser.add_argument("--demo", action="store_true", help="Run the full pipeline on a compact, focused demonstration dataset")
    parser.add_argument("--test", action="store_true", help="Execute test suite")

    args = parser.parse_args()

    if args.dashboard:
        launch_dashboard()
    elif args.demo:
        run_pipeline(log_path="logs/demo_logs.json", demo=True)
    elif args.test:
        print("[*] Running pytest suite...")
        subprocess.run([sys.executable, "-m", "pytest", "tests"])
    elif args.simulate:
        simulate_logs(num_logs=args.num_logs, output_file=args.file, inject_attacks=True)
    else:
        # Default behavior: run full pipeline
        run_pipeline(num_logs=args.num_logs, log_path=args.file, generate_new=True)


if __name__ == "__main__":
    main()
