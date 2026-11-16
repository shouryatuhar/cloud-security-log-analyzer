"""
Log Simulator Module
Simulates realistic AWS CloudTrail security events and multi-vector attack scenarios.
Course: CSET 462 - Cloud Security and Compliances
"""

import json
import random
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from faker import Faker

fake = Faker()

ACTIONS = [
    "LoginAttempt", "LogoutEvent", "FileDownload", "APICall",
    "RoleChange", "DeleteObject", "CreateBucket", "UploadFile",
    "DescribeInstances", "ConsoleLogin", "AttachUserPolicy",
    "CreateAccessKey", "StopLogging", "DeleteTrail", "AuthorizeSecurityGroupIngress"
]

USERS = [
    "admin", "manan.gupta", "shourya.tuhar", "mayank.sheoran",
    "mandeep.singh", "unknown_user", "root", "guest", "dev_service_account"
]

REGIONS = ["us-east-1", "us-west-2", "ap-south-1", "eu-west-1"]
SERVICES = ["IAM", "S3", "EC2", "CloudTrail", "Lambda"]
STATUSES = ["Success", "Success", "Success", "Failed", "Failed", "Unauthorized"]

# Known malicious / threat simulation actor IPs
ATTACKER_IPS = [
    "198.51.100.45",   # External Tor Exit / Botnet IP
    "203.0.113.88",    # Suspicious scanning IP
    "192.0.2.142",     # Brute force source
    "185.220.101.5"    # Anonymized proxy
]


def generate_log_entry(timestamp, event_source=None, event_name=None, user_name=None,
                       ip_address=None, region=None, status=None, bytes_transferred=None,
                       mfa_used=False, error_message=None):
    """
    Generates a single synthetic cloud log entry structured similarly to AWS CloudTrail.
    """
    source = event_source or random.choice(SERVICES)
    action = event_name or random.choice(ACTIONS)
    user = user_name or random.choice(USERS)
    ip = ip_address or fake.ipv4()
    reg = region or random.choice(REGIONS)
    stat = status or random.choice(STATUSES)
    b_transferred = bytes_transferred if bytes_transferred is not None else random.randint(0, 50000)

    # Contextual error code if failed
    error_code = None
    if stat == "Failed":
        error_code = "AccessDeniedException" if not error_message else "AuthFailure"
    elif stat == "Unauthorized":
        error_code = "UnauthorizedOperation"

    return {
        "eventTime": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source,
        "eventName": action,
        "userIdentity": {
            "type": "IAMUser" if user != "root" else "Root",
            "principalId": f"AIDA{random.randint(100000, 999999)}",
            "arn": f"arn:aws:iam::123456789012:{'root' if user == 'root' else 'user/' + user}",
            "userName": user,
            "ipAddress": ip
        },
        "awsRegion": reg,
        "status": stat,
        "errorCode": error_code,
        "errorMessage": error_message,
        "mfaUsed": mfa_used if user != "root" else False,
        "bytesTransferred": b_transferred,
        "requestParameters": {
            "bucketName": f"cset462-corp-data-{reg}" if source == "S3" else None,
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess" if action == "AttachUserPolicy" else None
        }
    }


def inject_attack_scenarios(base_time, attacker_ip=None):
    """
    Injects realistic, deliberate multi-stage cyber attacks into the dataset:
    1. Brute-Force Authentication attack
    2. Privilege Escalation via IAM
    3. Mass S3 Data Exfiltration & Deletion
    4. Root Account direct usage (CIS violation)
    5. CloudTrail defense impairment / tampering
    6. Impossible Travel / Geolocation Anomaly
    """
    injected_logs = []
    attacker_ip = attacker_ip or random.choice(ATTACKER_IPS)

    # Attack 1: Brute-Force Password Guessing on 'admin'
    bf_start = base_time + timedelta(hours=random.randint(10, 20))
    for i in range(8):
        t = bf_start + timedelta(seconds=i * 25)
        injected_logs.append(generate_log_entry(
            timestamp=t,
            event_source="IAM",
            event_name="LoginAttempt",
            user_name="admin",
            ip_address=attacker_ip,
            region="us-east-1",
            status="Failed",
            bytes_transferred=120,
            error_message="Invalid credentials"
        ))
    # Finally one unauthorized bypass attempt
    injected_logs.append(generate_log_entry(
        timestamp=bf_start + timedelta(seconds=220),
        event_source="IAM",
        event_name="LoginAttempt",
        user_name="admin",
        ip_address=attacker_ip,
        region="us-east-1",
        status="Unauthorized",
        bytes_transferred=250,
        error_message="User account locked due to excessive failed attempts"
    ))

    # Attack 2: IAM Privilege Escalation by 'guest'
    priv_time = base_time + timedelta(hours=random.randint(25, 35))
    injected_logs.append(generate_log_entry(
        timestamp=priv_time,
        event_source="IAM",
        event_name="AttachUserPolicy",
        user_name="guest",
        ip_address=attacker_ip,
        region="us-east-1",
        status="Unauthorized",
        bytes_transferred=450,
        error_message="AccessDenied: guest is not authorized to perform: iam:AttachUserPolicy"
    ))
    injected_logs.append(generate_log_entry(
        timestamp=priv_time + timedelta(minutes=2),
        event_source="IAM",
        event_name="CreateAccessKey",
        user_name="guest",
        ip_address=attacker_ip,
        region="us-east-1",
        status="Unauthorized",
        bytes_transferred=310
    ))

    # Attack 3: S3 Massive Data Exfiltration followed by Deletion
    exfil_time = base_time + timedelta(hours=random.randint(40, 55))
    for i in range(5):
        t = exfil_time + timedelta(minutes=i * 2)
        injected_logs.append(generate_log_entry(
            timestamp=t,
            event_source="S3",
            event_name="FileDownload",
            user_name="unknown_user",
            ip_address="203.0.113.88",
            region="us-west-2",
            status="Success",
            bytes_transferred=random.randint(25000000, 65000000)  # 25MB - 65MB per request
        ))
    injected_logs.append(generate_log_entry(
        timestamp=exfil_time + timedelta(minutes=15),
        event_source="S3",
        event_name="DeleteObject",
        user_name="unknown_user",
        ip_address="203.0.113.88",
        region="us-west-2",
        status="Success",
        bytes_transferred=100
    ))

    # Attack 4: Root User Activity (Severe CIS Benchmark Violation)
    root_time = base_time + timedelta(hours=random.randint(60, 75))
    injected_logs.append(generate_log_entry(
        timestamp=root_time,
        event_source="IAM",
        event_name="ConsoleLogin",
        user_name="root",
        ip_address="185.220.101.5",
        region="us-east-1",
        status="Success",
        bytes_transferred=1500,
        mfa_used=False
    ))
    injected_logs.append(generate_log_entry(
        timestamp=root_time + timedelta(minutes=3),
        event_source="EC2",
        event_name="AuthorizeSecurityGroupIngress",
        user_name="root",
        ip_address="185.220.101.5",
        region="us-east-1",
        status="Success",
        bytes_transferred=800
    ))

    # Attack 5: CloudTrail Auditing Defense Impairment
    tamper_time = base_time + timedelta(hours=random.randint(80, 95))
    injected_logs.append(generate_log_entry(
        timestamp=tamper_time,
        event_source="CloudTrail",
        event_name="StopLogging",
        user_name="unknown_user",
        ip_address="198.51.100.45",
        region="us-east-1",
        status="Unauthorized",
        bytes_transferred=320,
        error_message="UnauthorizedOperation: Action not permitted"
    ))

    # Attack 6: Impossible Travel / Rapid Geo-Dispersion
    travel_time = base_time + timedelta(hours=random.randint(100, 115))
    injected_logs.append(generate_log_entry(
        timestamp=travel_time,
        event_source="IAM",
        event_name="LoginAttempt",
        user_name="shourya.tuhar",
        ip_address="103.21.244.10",  # New Delhi, India
        region="ap-south-1",
        status="Success",
        bytes_transferred=2100
    ))
    injected_logs.append(generate_log_entry(
        timestamp=travel_time + timedelta(minutes=4),  # Only 4 minutes later
        event_source="IAM",
        event_name="LoginAttempt",
        user_name="shourya.tuhar",
        ip_address="185.220.101.5",   # Frankfurt, Germany
        region="eu-west-1",
        status="Success",
        bytes_transferred=2200
    ))

    return injected_logs


def simulate_logs(num_logs=250, output_file="logs/cloud_logs.json", seed=42, inject_attacks=True):
    """
    Generates synthetic cloud logs with guaranteed attack scenario injections
    and normal operational traffic.
    """
    random.seed(seed)
    Faker.seed(seed)

    base_time = datetime.now(timezone.utc) - timedelta(days=7)
    logs = []

    # 1. Collect attack scenarios if requested
    attacks = inject_attack_scenarios(base_time) if inject_attacks else []

    # 2. Generate normal operational logs to reach num_logs
    needed_normal = max(0, num_logs - len(attacks))
    for _ in range(needed_normal):
        timestamp = base_time + timedelta(minutes=random.randint(0, 10080))
        logs.append(generate_log_entry(timestamp))

    logs.extend(attacks)

    # Sort chronologically
    logs.sort(key=lambda entry: entry["eventTime"])

    # Ensure parent output directory exists
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)

    print(f"Generated {len(logs)} simulated cloud records (with attack scenarios) -> {output_file}")
    return logs


def simulate_demo_logs(output_file="logs/demo_logs.json", seed=42):
    """Create a compact, repeatable dataset with a few explainable findings."""
    random.seed(seed)
    Faker.seed(seed)
    base_time = datetime.now(timezone.utc).replace(hour=9, minute=0, second=0, microsecond=0) - timedelta(days=1)
    logs = []

    # Ordinary activity gives the parser and analytics a clean baseline.
    normal_events = [
        ("IAM", "ConsoleLogin", "alice", "10.0.0.10", "us-east-1", "Success", 1200, True),
        ("S3", "GetObject", "alice", "10.0.0.10", "us-east-1", "Success", 4200, True),
        ("EC2", "DescribeInstances", "devops", "10.0.0.11", "us-east-1", "Success", 800, True),
        ("Lambda", "Invoke", "service-role", "10.0.0.12", "us-west-2", "Success", 900, True),
        ("S3", "PutObject", "alice", "10.0.0.10", "us-east-1", "Success", 2200, True),
        ("IAM", "ListUsers", "auditor", "10.0.0.13", "us-east-1", "Success", 500, True),
        ("EC2", "DescribeInstances", "devops", "10.0.0.11", "us-east-1", "Success", 750, True),
        ("S3", "GetObject", "alice", "10.0.0.10", "us-east-1", "Success", 3100, True),
    ]
    for index, event in enumerate(normal_events):
        source, name, user, ip, region, status, size, mfa = event
        logs.append(generate_log_entry(base_time + timedelta(minutes=index * 7), source, name, user, ip, region, status, size, mfa))

    scenarios = [
        # Three failed logins from one IP trigger one brute-force finding.
        ("IAM", "LoginAttempt", "admin", "192.0.2.142", "us-east-1", "Failed", 120, False),
        ("IAM", "LoginAttempt", "admin", "192.0.2.142", "us-east-1", "Failed", 120, False),
        ("IAM", "LoginAttempt", "admin", "192.0.2.142", "us-east-1", "Failed", 120, False),
        # One example each of privilege escalation, exfiltration, root use, and trail tampering.
        ("IAM", "AttachUserPolicy", "guest", "203.0.113.88", "us-east-1", "Unauthorized", 450, False),
        ("S3", "FileDownload", "unknown_user", "203.0.113.88", "us-west-2", "Success", 25000000, False),
        ("IAM", "ConsoleLogin", "root", "185.220.101.5", "us-east-1", "Success", 1500, False),
        ("CloudTrail", "StopLogging", "unknown_user", "198.51.100.45", "us-east-1", "Unauthorized", 320, False),
        # Same user appears in distant regions four minutes apart.
        ("IAM", "LoginAttempt", "shourya.tuhar", "103.21.244.10", "ap-south-1", "Success", 2100, True),
        ("IAM", "LoginAttempt", "shourya.tuhar", "185.220.101.5", "eu-west-1", "Success", 2200, True),
    ]
    for index, event in enumerate(scenarios):
        source, name, user, ip, region, status, size, mfa = event
        logs.append(generate_log_entry(base_time + timedelta(hours=2, minutes=index * 4), source, name, user, ip, region, status, size, mfa))

    logs.sort(key=lambda entry: entry["eventTime"])
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)
    print(f"Generated {len(logs)} focused demo records -> {output_file}")
    return logs


if __name__ == "__main__":
    simulate_logs(num_logs=300, output_file="../logs/cloud_logs.json")
