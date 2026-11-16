"""
Alerting and Triage Module
Formats, triages, and notifies security operations teams of detected threats.
Course: CSET 462 - Cloud Security and Compliances
"""

from typing import List, Dict, Any
from datetime import datetime


class AlertManager:
    """
    Manages security alert generation, severity scoring, and alert routing.
    """

    SEVERITY_COLORS = {
        "CRITICAL": "\033[91m",  # Bright Red
        "HIGH": "\033[31m",      # Red
        "MEDIUM": "\033[33m",    # Yellow
        "LOW": "\033[36m",       # Cyan
        "RESET": "\033[0m"
    }

    def __init__(self, incidents: List[Dict[str, Any]]):
        self.incidents = incidents

    def get_severity_breakdown(self) -> Dict[str, int]:
        """Returns counts of incidents by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for inc in self.incidents:
            sev = inc.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def generate_siem_events(self) -> List[Dict[str, Any]]:
        """
        Converts incidents into standard SIEM Common Event Format (CEF) / JSON
        suitable for ingestion into Splunk, Microsoft Sentinel, or AWS Security Hub.
        """
        siem_events = []
        for inc in self.incidents:
            siem_events.append({
                "source": "PythonCloudLogAnalyzer",
                "event_id": inc["incident_id"],
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "incident_timestamp": inc["timestamp"],
                "severity": inc["severity"],
                "confidence_score": inc.get("confidence", 90),
                "rule": {
                    "id": inc["rule_id"],
                    "name": inc["rule_name"],
                    "mitre_technique": inc["mitre_technique"]
                },
                "entities": {
                    "user": inc["actor_user"],
                    "source_ip": inc["actor_ip"],
                    "target_resource": inc["resource"]
                },
                "details": inc["description"],
                "raw_evidence": inc.get("evidence", {})
            })
        return siem_events

    def format_terminal_alerts(self, max_display: int = 10) -> str:
        """Formats incidents into a high-visibility terminal alert banner."""
        if not self.incidents:
            return "No security incidents detected. Cloud environment is clean."

        lines = [
            "=" * 78,
            "                   SECURITY INCIDENT ALERT FEED                   ",
            "=" * 78
        ]

        for inc in self.incidents[:max_display]:
            sev = inc["severity"]
            color = self.SEVERITY_COLORS.get(sev, "")
            reset = self.SEVERITY_COLORS["RESET"]

            lines.append(f"[{color}{sev}{reset}] {inc['incident_id']} | {inc['rule_name']}")
            lines.append(f"   Time       : {inc['timestamp']}")
            lines.append(f"   Technique  : {inc['mitre_technique']}")
            lines.append(f"   Actor/IP   : User='{inc['actor_user']}' | IP={inc['actor_ip']}")
            lines.append(f"   Resource   : {inc['resource']}")
            lines.append(f"   Description: {inc['description']}")
            lines.append("-" * 78)

        if len(self.incidents) > max_display:
            lines.append(f"... and {len(self.incidents) - max_display} more incidents logged.")

        return "\n".join(lines)
