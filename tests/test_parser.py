"""
Unit tests for Log Parser
Course: CSET 462 - Cloud Security and Compliances
"""

import unittest
from datetime import datetime, timezone
from src.log_simulator import generate_log_entry
from src.log_parser import LogParser


class TestLogParser(unittest.TestCase):

    def setUp(self):
        self.parser = LogParser()
        now = datetime.now(timezone.utc)
        self.sample_logs = [
            generate_log_entry(now, user_name="admin", status="Success"),
            generate_log_entry(now, user_name="root", status="Success"),
            generate_log_entry(now, user_name="guest", status="Failed")
        ]

    def test_parse_to_dataframe(self):
        df = self.parser.parse_to_dataframe(self.sample_logs)
        self.assertEqual(len(df), 3)
        self.assertIn("userName", df.columns)
        self.assertIn("is_root", df.columns)
        self.assertIn("is_failed", df.columns)

        # Check root flag
        self.assertTrue(df[df["userName"] == "root"]["is_root"].iloc[0])

    def test_summary_statistics(self):
        self.parser.parse_to_dataframe(self.sample_logs)
        stats = self.parser.get_summary_statistics()

        self.assertEqual(stats["total_events"], 3)
        self.assertEqual(stats["root_events_count"], 1)
        self.assertEqual(stats["failed_count"], 1)


if __name__ == "__main__":
    unittest.main()
