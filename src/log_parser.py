"""
Log Parser Module
Ingests, flattens, validates, and enriches simulated cloud security logs.
Course: CSET 462 - Cloud Security and Compliances
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Union
import pandas as pd


class LogParser:
    """
    Parser for CloudTrail-style synthetic and real cloud logs.
    Handles JSON file loading, schema normalization, flattening, and feature enrichment.
    """

    EXPECTED_COLUMNS = [
        "eventTime", "eventSource", "eventName", "userName",
        "userType", "userArn", "ipAddress", "awsRegion",
        "status", "errorCode", "errorMessage", "mfaUsed", "bytesTransferred"
    ]

    def __init__(self, log_path: Union[str, Path] = None):
        self.log_path = Path(log_path) if log_path else None
        self.raw_logs: List[Dict[str, Any]] = []
        self.df: pd.DataFrame = pd.DataFrame()

    def load_json(self, file_path: Union[str, Path] = None) -> List[Dict[str, Any]]:
        """Loads log records from a JSON file."""
        path = Path(file_path) if file_path else self.log_path
        if not path or not path.exists():
            raise FileNotFoundError(f"Log file not found at: {path}")

        with open(path, "r", encoding="utf-8") as f:
            self.raw_logs = json.load(f)

        if not isinstance(self.raw_logs, list):
            raise ValueError("Expected a JSON array of log records.")

        return self.raw_logs

    def parse_to_dataframe(self, logs: List[Dict[str, Any]] = None) -> pd.DataFrame:
        """
        Flattens nested JSON records into a structured pandas DataFrame
        with normalized data types and enriched security fields.
        """
        records = logs if logs is not None else self.raw_logs
        if not records:
            if self.log_path and self.log_path.exists():
                records = self.load_json()
            else:
                return pd.DataFrame(columns=self.EXPECTED_COLUMNS)

        flattened = []
        for entry in records:
            user_identity = entry.get("userIdentity", {})
            req_params = entry.get("requestParameters", {}) or {}

            flattened.append({
                "eventTime": entry.get("eventTime"),
                "eventSource": entry.get("eventSource", "Unknown"),
                "eventName": entry.get("eventName", "Unknown"),
                "userName": user_identity.get("userName", "unknown_user"),
                "userType": user_identity.get("type", "IAMUser"),
                "userArn": user_identity.get("arn", ""),
                "ipAddress": user_identity.get("ipAddress", "0.0.0.0"),
                "awsRegion": entry.get("awsRegion", "global"),
                "status": entry.get("status", "Unknown"),
                "errorCode": entry.get("errorCode"),
                "errorMessage": entry.get("errorMessage"),
                "mfaUsed": bool(entry.get("mfaUsed", False)),
                "bytesTransferred": int(entry.get("bytesTransferred", 0)),
                "bucketName": req_params.get("bucketName"),
                "policyArn": req_params.get("policyArn")
            })

        df = pd.DataFrame(flattened)

        # Datetime normalization
        df["eventTime"] = pd.to_datetime(df["eventTime"], utc=True, errors="coerce")
        df.sort_values(by="eventTime", inplace=True)
        df.reset_index(drop=True, inplace=True)

        # Enrich features for security analysis
        df["hour"] = df["eventTime"].dt.hour
        df["day_name"] = df["eventTime"].dt.day_name()
        df["is_failed"] = df["status"].isin(["Failed", "Unauthorized"])
        df["is_root"] = (df["userName"] == "root") | (df["userType"] == "Root")
        df["is_unauthorized"] = df["status"] == "Unauthorized"

        # Categorize data transfer volume
        df["data_volume_category"] = pd.cut(
            df["bytesTransferred"],
            bins=[-1, 1000, 100000, 10000000, float("inf")],
            labels=["Low", "Medium", "High", "CriticalExfiltration"]
        )

        self.df = df
        return df

    def get_summary_statistics(self) -> Dict[str, Any]:
        """
        Computes high-level summary statistics across the parsed cloud logs.
        """
        if self.df.empty:
            return {"error": "No logs loaded"}

        return {
            "total_events": len(self.df),
            "unique_users": int(self.df["userName"].nunique()),
            "unique_ips": int(self.df["ipAddress"].nunique()),
            "unique_services": int(self.df["eventSource"].nunique()),
            "success_count": int((self.df["status"] == "Success").sum()),
            "failed_count": int((self.df["status"] == "Failed").sum()),
            "unauthorized_count": int((self.df["status"] == "Unauthorized").sum()),
            "root_events_count": int(self.df["is_root"].sum()),
            "total_bytes_transferred": int(self.df["bytesTransferred"].sum()),
            "date_range_start": str(self.df["eventTime"].min()),
            "date_range_end": str(self.df["eventTime"].max()),
            "top_actions": self.df["eventName"].value_counts().head(5).to_dict(),
            "top_users": self.df["userName"].value_counts().head(5).to_dict(),
            "top_ips": self.df["ipAddress"].value_counts().head(5).to_dict(),
            "services_breakdown": self.df["eventSource"].value_counts().to_dict(),
            "regions_breakdown": self.df["awsRegion"].value_counts().to_dict()
        }


def parse_cloud_logs(file_path: str = "logs/cloud_logs.json") -> pd.DataFrame:
    """Convenience helper function to parse logs directly."""
    parser = LogParser(file_path)
    parser.load_json()
    return parser.parse_to_dataframe()
