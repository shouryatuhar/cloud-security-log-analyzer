"""
Unit tests for Threat Detector
Course: CSET 462 - Cloud Security and Compliances
"""

import unittest
from datetime import datetime, timezone, timedelta
from src.log_simulator import generate_log_entry
from src.log_parser import LogParser
from src.threat_detector import ThreatDetector


class TestThreatDetector(unittest.TestCase):

    def test_brute_force_detection(self):
        base = datetime.now(timezone.utc)
        logs = []
        # Inject 4 failed logins from same IP within 5 mins
        for i in range(4):
            logs.append(generate_log_entry(
                timestamp=base + timedelta(seconds=i*30),
                event_name="LoginAttempt",
                user_name="admin",
                ip_address="198.51.100.99",
                status="Failed"
            ))

        parser = LogParser()
        df = parser.parse_to_dataframe(logs)
        detector = ThreatDetector(df)
        incidents = detector.detect_all()

        bf_incidents = [i for i in incidents if i["rule_id"] == "RULE-001"]
        self.assertGreaterEqual(len(bf_incidents), 1)
        self.assertEqual(bf_incidents[0]["actor_ip"], "198.51.100.99")

    def test_root_detection(self):
        base = datetime.now(timezone.utc)
        logs = [
            generate_log_entry(timestamp=base, user_name="root", event_name="ConsoleLogin", status="Success")
        ]
        parser = LogParser()
        df = parser.parse_to_dataframe(logs)
        detector = ThreatDetector(df)
        incidents = detector.detect_all()

        root_incidents = [i for i in incidents if i["rule_id"] == "RULE-004"]
        self.assertEqual(len(root_incidents), 1)
        self.assertEqual(root_incidents[0]["actor_user"], "root")


if __name__ == "__main__":
    unittest.main()
