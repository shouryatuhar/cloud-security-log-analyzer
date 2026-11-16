"""
Visualizer Module
Generates cybersecurity analytics charts, threat timelines, and compliance graphs.
Course: CSET 462 - Cloud Security and Compliances
"""

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless environments
import matplotlib.pyplot as plt
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any

# Set modern aesthetic theme
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.size"] = 10


class SecurityVisualizer:
    """
    Creates and saves publication-quality cybersecurity charts for reports and dashboards.
    """

    def __init__(self, df: pd.DataFrame, incidents: List[Dict[str, Any]], output_dir: str = "reports/charts"):
        self.df = df
        self.incidents = incidents
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all_charts(self) -> Dict[str, str]:
        """Generates all standard security visual assets."""
        generated = {}
        if not self.df.empty:
            generated["service_breakdown"] = self.plot_service_breakdown()
            generated["timeline"] = self.plot_timeline_activity()
            generated["top_actors"] = self.plot_top_threat_actors()

        if self.incidents:
            generated["severity_donut"] = self.plot_incident_severity()
            generated["mitre_matrix"] = self.plot_mitre_techniques()

        return generated

    def plot_incident_severity(self) -> str:
        """Donut chart of incident severity distribution."""
        fig, ax = plt.subplots(figsize=(6, 5))
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for inc in self.incidents:
            s = inc.get("severity", "LOW")
            counts[s] = counts.get(s, 0) + 1

        labels = [k for k, v in counts.items() if v > 0]
        sizes = [counts[k] for k in labels]
        colors = {"CRITICAL": "#e63946", "HIGH": "#f4a261", "MEDIUM": "#e9c46a", "LOW": "#2a9d8f"}
        plot_colors = [colors.get(l, "#457b9d") for l in labels]

        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            autopct="%1.1f%%",
            startangle=140,
            colors=plot_colors,
            wedgeprops=dict(width=0.4, edgecolor="white", linewidth=2)
        )
        for t in texts:
            t.set_fontsize(11)
            t.set_weight("bold")
        for at in autotexts:
            at.set_fontsize(10)
            at.set_color("white")
            at.set_weight("bold")

        ax.set_title("Security Incidents by Severity", fontsize=13, fontweight="bold", pad=15)
        path = self.output_dir / "incident_severity.png"
        fig.tight_layout()
        fig.savefig(path, dpi=200)
        plt.close(fig)
        return str(path)

    def plot_service_breakdown(self) -> str:
        """Bar chart of cloud service activity categorized by Success vs Failure."""
        fig, ax = plt.subplots(figsize=(8, 4.5))
        ct = pd.crosstab(self.df["eventSource"], self.df["status"])
        ct.plot(
            kind="bar",
            stacked=True,
            ax=ax,
            color={"Success": "#2a9d8f", "Failed": "#f4a261", "Unauthorized": "#e63946"},
            edgecolor="white"
        )
        ax.set_title("Cloud Service Activity Distribution by Status", fontsize=13, fontweight="bold")
        ax.set_xlabel("Simulated Cloud Service", fontweight="bold")
        ax.set_ylabel("Event Count", fontweight="bold")
        ax.legend(title="Status", frameon=True)
        plt.xticks(rotation=0)
        path = self.output_dir / "service_breakdown.png"
        fig.tight_layout()
        fig.savefig(path, dpi=200)
        plt.close(fig)
        return str(path)

    def plot_mitre_techniques(self) -> str:
        """Horizontal bar chart showing detected MITRE ATT&CK techniques."""
        fig, ax = plt.subplots(figsize=(9, 4.5))
        techniques = [inc.get("mitre_technique", "Unknown") for inc in self.incidents]
        series = pd.Series(techniques).value_counts().sort_values(ascending=True)

        bars = ax.barh(series.index, series.values, color="#1d3557", edgecolor="white", height=0.6)
        ax.set_title("Detected Threats Mapped to MITRE ATT&CK", fontsize=13, fontweight="bold")
        ax.set_xlabel("Incident Count", fontweight="bold")

        for bar in bars:
            width = bar.get_width()
            ax.text(width + 0.1, bar.get_y() + bar.get_height()/2, f"{int(width)}",
                    va="center", ha="left", fontsize=10, fontweight="bold", color="#1d3557")

        path = self.output_dir / "mitre_techniques.png"
        fig.tight_layout()
        fig.savefig(path, dpi=200)
        plt.close(fig)
        return str(path)

    def plot_timeline_activity(self) -> str:
        """Time-series chart showing event distribution over time."""
        fig, ax = plt.subplots(figsize=(10, 4.5))
        df_copy = self.df.copy()
        df_copy.set_index("eventTime", inplace=True)

        resampled_all = df_copy["eventName"].resample("6h").count()
        resampled_failed = df_copy[df_copy["is_failed"]]["eventName"].resample("6h").count().reindex(resampled_all.index, fill_value=0)

        ax.plot(resampled_all.index, resampled_all.values, label="Total Activity", color="#457b9d", lw=2)
        ax.fill_between(resampled_all.index, resampled_all.values, color="#457b9d", alpha=0.15)

        ax.plot(resampled_failed.index, resampled_failed.values, label="Failed/Unauthorized Spikes", color="#e63946", lw=2.5, linestyle="--")
        ax.fill_between(resampled_failed.index, resampled_failed.values, color="#e63946", alpha=0.2)

        ax.set_title("Cloud Security Event Timeline (6-Hour Windows)", fontsize=13, fontweight="bold")
        ax.set_xlabel("Event Timestamp (UTC)", fontweight="bold")
        ax.set_ylabel("Event Count", fontweight="bold")
        ax.legend(frameon=True)
        fig.autofmt_xdate()

        path = self.output_dir / "timeline_activity.png"
        fig.tight_layout()
        fig.savefig(path, dpi=200)
        plt.close(fig)
        return str(path)

    def plot_top_threat_actors(self) -> str:
        """Bar charts showing top suspicious IP addresses and targeted users."""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

        failed_df = self.df[self.df["is_failed"]]
        if not failed_df.empty:
            top_ips = failed_df["ipAddress"].value_counts().head(5)
            top_users = failed_df["userName"].value_counts().head(5)

            ip_colors = plt.cm.Reds([0.45 + 0.5 * i / max(len(top_ips) - 1, 1) for i in range(len(top_ips))])
            ax1.barh(top_ips.index, top_ips.values, color=ip_colors)
            ax1.invert_yaxis()
            ax1.set_title("Top Offending Source IPs", fontweight="bold", fontsize=11)
            ax1.set_xlabel("Failed/Unauthorized Events", fontweight="bold")

            user_colors = plt.cm.Oranges([0.45 + 0.5 * i / max(len(top_users) - 1, 1) for i in range(len(top_users))])
            ax2.barh(top_users.index, top_users.values, color=user_colors)
            ax2.invert_yaxis()
            ax2.set_title("Top Targeted / Suspicious Users", fontweight="bold", fontsize=11)
            ax2.set_xlabel("Failed/Unauthorized Events", fontweight="bold")
        else:
            ax1.text(0.5, 0.5, "No failed events", ha="center")
            ax2.text(0.5, 0.5, "No failed events", ha="center")

        path = self.output_dir / "top_threat_actors.png"
        fig.tight_layout()
        fig.savefig(path, dpi=200)
        plt.close(fig)
        return str(path)
