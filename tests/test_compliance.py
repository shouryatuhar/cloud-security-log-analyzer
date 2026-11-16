"""
Unit tests for Compliance Checker
Course: CSET 462 - Cloud Security and Compliances
"""

import unittest
from datetime import datetime, timezone
from src.log_simulator import generate_log_entry
from src.log_parser import LogParser
from src.compliance_checker import ComplianceChecker


class TestComplianceChecker(unittest.TestCase):

    def test_compliance_clean(self):
        now = datetime.now(timezone.utc)
        clean_logs = [
            generate_log_entry(now, user_name="manan.gupta", event_name="APICall", status="Success", mfa_used=True),
            generate_log_entry(now, user_name="shourya.tuhar", event_name="DescribeInstances", status="Success", mfa_used=True)
        ]
        parser = LogParser()
        df = parser.parse_to_dataframe(clean_logs)
        checker = ComplianceChecker(df)
        res = checker.run_all_checks()

        self.assertIn("compliance_score_percent", res)
        # Root check should pass because no root activity
        root_check = next(c for c in res["checks"] if c["control_id"] == "CIS-1.1")
        self.assertEqual(root_check["status"], "PASSED")

    def test_compliance_root_failure(self):
        now = datetime.now(timezone.utc)
        root_logs = [
            generate_log_entry(now, user_name="root", event_name="ConsoleLogin", status="Success")
        ]
        parser = LogParser()
        df = parser.parse_to_dataframe(root_logs)
        checker = ComplianceChecker(df)
        res = checker.run_all_checks()

        root_check = next(c for c in res["checks"] if c["control_id"] == "CIS-1.1")
        self.assertEqual(root_check["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
