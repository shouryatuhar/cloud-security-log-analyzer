"""
Unit tests for Log Simulator
Course: CSET 462 - Cloud Security and Compliances
"""

import unittest
from datetime import datetime, timezone
from src.log_simulator import generate_log_entry, simulate_logs, inject_attack_scenarios


class TestLogSimulator(unittest.TestCase):

    def test_generate_log_entry_structure(self):
        now = datetime.now(timezone.utc)
        entry = generate_log_entry(now)

        self.assertIn("eventTime", entry)
        self.assertIn("eventSource", entry)
        self.assertIn("eventName", entry)
        self.assertIn("userIdentity", entry)
        self.assertIn("userName", entry["userIdentity"])
        self.assertIn("ipAddress", entry["userIdentity"])
        self.assertIn("awsRegion", entry)
        self.assertIn("status", entry)
        self.assertIn("bytesTransferred", entry)

    def test_attack_scenario_injection(self):
        now = datetime.now(timezone.utc)
        attacks = inject_attack_scenarios(now)

        self.assertGreater(len(attacks), 5)
        # Check that root user event is present
        root_events = [e for e in attacks if e["userIdentity"]["userName"] == "root"]
        self.assertGreater(len(root_events), 0)

        # Check for brute force failure attempts
        failed_logins = [e for e in attacks if e["eventName"] == "LoginAttempt" and e["status"] == "Failed"]
        self.assertGreater(len(failed_logins), 3)

    def test_simulate_logs_count(self):
        logs = simulate_logs(num_logs=50, output_file="logs/test_logs.json", seed=123)
        self.assertGreaterEqual(len(logs), 50)


if __name__ == "__main__":
    unittest.main()
