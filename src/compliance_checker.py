"""
Compliance Checker Module
Automates CIS AWS Foundations Benchmark v3.0 and Cloud Compliance Auditing.
Course: CSET 462 - Cloud Security and Compliances
"""

import pandas as pd
from typing import Dict, Any, List


class ComplianceChecker:
    """
    Evaluates simulated cloud logs against CIS AWS Foundations Benchmark v3.0
    and cloud compliance governance controls (SOC 2, ISO 27001).
    """

    def __init__(self, df: pd.DataFrame):
        self.df = df.copy()
        self.results: List[Dict[str, Any]] = []

    def run_all_checks(self) -> Dict[str, Any]:
        """Runs the entire compliance audit suite."""
        self.results = []
        if self.df.empty:
            return {"error": "Empty log dataset"}

        self.check_cis_1_1_root_usage()
        self.check_cis_1_16_direct_iam_policy_attachment()
        self.check_cis_1_4_access_key_creation()
        self.check_cis_3_1_unauthorized_api_calls()
        self.check_cis_3_2_console_mfa()
        self.check_cis_3_3_cloudtrail_continuous_logging()
        self.check_cis_2_1_s3_data_tampering()

        total = len(self.results)
        passed = sum(1 for r in self.results if r["status"] == "PASSED")
        failed = sum(1 for r in self.results if r["status"] == "FAILED")
        warnings = sum(1 for r in self.results if r["status"] == "WARNING")
        score = round((passed / total) * 100, 1) if total > 0 else 0.0

        if score >= 85:
            rating = "GOOD (Generally Compliant)"
            rating_color = "green"
        elif score >= 60:
            rating = "MODERATE (Remediation Required)"
            rating_color = "yellow"
        else:
            rating = "POOR (High Compliance Risk)"
            rating_color = "red"

        return {
            "total_checks": total,
            "passed_checks": passed,
            "failed_checks": failed,
            "warning_checks": warnings,
            "compliance_score_percent": score,
            "compliance_rating": rating,
            "rating_color": rating_color,
            "checks": self.results
        }

    def _add_check(self, control_id: str, title: str, standard: str,
                   status: str, severity: str, details: str, remediation: str,
                   evidence_count: int = 0):
        self.results.append({
            "control_id": control_id,
            "title": title,
            "standard": standard,
            "status": status,
            "severity": severity,
            "details": details,
            "remediation": remediation,
            "evidence_count": evidence_count
        })

    def check_cis_1_1_root_usage(self):
        """CIS 1.1: Ensure root user is not used for everyday administrative tasks."""
        root_events = self.df[self.df["is_root"]]
        count = len(root_events)
        if count == 0:
            self._add_check(
                control_id="CIS-1.1",
                title="Avoid Root Account Usage",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="PASSED",
                severity="CRITICAL",
                details="No activity detected from the root account. Good security posture.",
                remediation="Continue enforcing root account lock-down with hardware MFA."
            )
        else:
            self._add_check(
                control_id="CIS-1.1",
                title="Avoid Root Account Usage",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="FAILED",
                severity="CRITICAL",
                details=f"Detected {count} event(s) executed directly by the root account.",
                remediation="Lock root account credentials in a secure vault, enable hardware MFA, and provision least-privilege IAM roles.",
                evidence_count=count
            )

    def check_cis_1_16_direct_iam_policy_attachment(self):
        """CIS 1.16: Ensure IAM policies are attached only to groups or roles."""
        user_policy_events = self.df[self.df["eventName"].isin(["AttachUserPolicy", "PutUserPolicy"])]
        count = len(user_policy_events)
        if count == 0:
            self._add_check(
                control_id="CIS-1.16",
                title="Ensure IAM Policies Are Attached Only to Groups/Roles",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="PASSED",
                severity="HIGH",
                details="No direct user policy attachments detected.",
                remediation="Maintain group-based and role-based access control (RBAC)."
            )
        else:
            self._add_check(
                control_id="CIS-1.16",
                title="Ensure IAM Policies Are Attached Only to Groups/Roles",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="FAILED",
                severity="HIGH",
                details=f"Detected {count} direct policy attachment action(s) targeting individual users.",
                remediation="Attach permissions policies exclusively to IAM groups or IAM roles to prevent permission drift.",
                evidence_count=count
            )

    def check_cis_1_4_access_key_creation(self):
        """CIS 1.4: Monitor access key generation and rotation."""
        key_events = self.df[self.df["eventName"] == "CreateAccessKey"]
        count = len(key_events)
        if count == 0:
            self._add_check(
                control_id="CIS-1.4",
                title="Access Key Lifecycle Monitoring",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="PASSED",
                severity="MEDIUM",
                details="No suspicious or unauthorized access key creation events detected.",
                remediation="Enforce mandatory 90-day access key rotation and use temporary IAM roles where possible."
            )
        else:
            status = "FAILED" if any(key_events["status"].isin(["Unauthorized", "Failed"])) else "WARNING"
            self._add_check(
                control_id="CIS-1.4",
                title="Access Key Lifecycle Monitoring",
                standard="CIS AWS Foundations Benchmark v3.0",
                status=status,
                severity="MEDIUM",
                details=f"Detected {count} access key creation attempt(s). Some were unauthorized or abnormal.",
                remediation="Verify business justification for permanent programmatic keys and audit IAM user permissions.",
                evidence_count=count
            )

    def check_cis_3_1_unauthorized_api_calls(self):
        """CIS 3.1: Ensure metric filters and alerts exist for unauthorized API calls."""
        unauthorized = self.df[self.df["status"] == "Unauthorized"]
        count = len(unauthorized)
        if count == 0:
            self._add_check(
                control_id="CIS-3.1",
                title="Unauthorized API Calls Monitoring",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="PASSED",
                severity="HIGH",
                details="Zero unauthorized API calls detected in the sample logs.",
                remediation="Maintain CloudWatch metric filters for `{($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\")}`."
            )
        else:
            self._add_check(
                control_id="CIS-3.1",
                title="Unauthorized API Calls Monitoring",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="FAILED",
                severity="HIGH",
                details=f"Detected {count} unauthorized API call(s). Indicates potential reconnaissance or privilege testing.",
                remediation="Set up CloudWatch Alarms to immediately notify security operations whenever unauthorized API calls spike.",
                evidence_count=count
            )

    def check_cis_3_2_console_mfa(self):
        """CIS 3.2: Ensure multi-factor authentication (MFA) is enabled for console logins."""
        logins = self.df[self.df["eventName"].isin(["LoginAttempt", "ConsoleLogin"])]
        no_mfa = logins[logins["mfaUsed"] == False]
        count = len(no_mfa)
        if count == 0 and not logins.empty:
            self._add_check(
                control_id="CIS-3.2",
                title="MFA Enforcement for Console Logins",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="PASSED",
                severity="HIGH",
                details="All console logins were protected with MFA.",
                remediation="Continue enforcing MFA across all IAM users and SSO identities."
            )
        else:
            self._add_check(
                control_id="CIS-3.2",
                title="MFA Enforcement for Console Logins",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="FAILED",
                severity="HIGH",
                details=f"Detected {count} console login attempt(s) without multi-factor authentication (MFA).",
                remediation="Apply an IAM boundary policy that denies all console actions unless `aws:MultiFactorAuthPresent` is true.",
                evidence_count=count
            )

    def check_cis_3_3_cloudtrail_continuous_logging(self):
        """CIS 3.3: Ensure CloudTrail logging is continuously active and tamper-proof."""
        tamper = self.df[self.df["eventName"].isin(["StopLogging", "DeleteTrail"])]
        count = len(tamper)
        if count == 0:
            self._add_check(
                control_id="CIS-3.3",
                title="Continuous CloudTrail Logging & Tamper Resistance",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="PASSED",
                severity="CRITICAL",
                details="No actions attempted to stop or delete CloudTrail logging.",
                remediation="Enable S3 Object Lock and SCPs to prevent any IAM identity from stopping trails."
            )
        else:
            self._add_check(
                control_id="CIS-3.3",
                title="Continuous CloudTrail Logging & Tamper Resistance",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="FAILED",
                severity="CRITICAL",
                details=f"Detected {count} attempt(s) to disable or tamper with CloudTrail logging.",
                remediation="Enforce AWS Organizations Service Control Policies (SCPs) denying `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail`.",
                evidence_count=count
            )

    def check_cis_2_1_s3_data_tampering(self):
        """CIS 2.1: Ensure S3 object deletion and bulk downloads are audited."""
        deletions = self.df[self.df["eventName"].isin(["DeleteObject", "DeleteBucket"])]
        count = len(deletions)
        if count < 3:
            self._add_check(
                control_id="CIS-2.1",
                title="S3 Bucket & Object Protection",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="PASSED",
                severity="MEDIUM",
                details="Object deletion rate is within normal operational thresholds.",
                remediation="Enable S3 Versioning and MFA Delete on all sensitive production buckets."
            )
        else:
            self._add_check(
                control_id="CIS-2.1",
                title="S3 Bucket & Object Protection",
                standard="CIS AWS Foundations Benchmark v3.0",
                status="WARNING",
                severity="MEDIUM",
                details=f"Detected {count} S3 deletion event(s). Could indicate malicious data tampering or ransomware cleanup.",
                remediation="Enable S3 Object Lock in Compliance mode and require MFA Delete for bucket configuration changes.",
                evidence_count=count
            )
