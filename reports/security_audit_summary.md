# Cloud Security & Compliance Audit Report
**Course:** CSET 462 – Cloud Security and Compliances  
**Project:** Python-Based Cloud Security Log Analyzer  
**Team Members:** Shourya Tuhar (Leader), Manan Gupta, Mayank Sheoran, Mandeep Singh  
**Audit Timestamp:** 2026-11-06 14:31:11 UTC  

---

## Executive Summary
- **Total Cloud Events Analyzed:** 100
- **Detected Security Incidents:** 44
  - **CRITICAL:** 35 | **HIGH:** 9 | **MEDIUM:** 0 | **LOW:** 0
- **CIS Benchmark Compliance Score:** **0.0%** (POOR (High Compliance Risk))
- **Failed Compliance Controls:** 6 of 7

---

## 1. Threat Detection Findings (MITRE ATT&CK Mapped)
| Incident ID | Severity | Threat / Rule | MITRE Technique | Actor User | Source IP |
|---|---|---|---|---|---|
| `INC-0001` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `217.215.39.223` |
| `INC-0002` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `root` | `217.215.39.223` |
| `INC-0003` | **CRITICAL** | Brute-Force Authentication Attempt | `T1110.001 - Brute Force: Password Guessing` | `admin` | `198.51.100.45` |
| `INC-0004` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `109.175.48.85` |
| `INC-0005` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `194.205.250.139` |
| `INC-0006` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `root` | `194.205.250.139` |
| `INC-0007` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `shourya.tuhar` | `82.195.110.208` |
| `INC-0008` | **CRITICAL** | Unauthorized IAM Privilege Escalation | `T1098 - Account Manipulation` | `root` | `151.89.105.16` |
| `INC-0009` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `151.89.105.16` |
| `INC-0010` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `dev_service_account` | `166.193.42.206` |
| `INC-0011` | **CRITICAL** | Unauthorized IAM Privilege Escalation | `T1098 - Account Manipulation` | `guest` | `198.51.100.45` |
| `INC-0012` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `dev_service_account` | `72.239.180.7` |
| `INC-0013` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `174.228.160.231` |
| `INC-0014` | **CRITICAL** | Massive S3 Data Exfiltration | `T1530 - Data from Cloud Storage` | `unknown_user` | `203.0.113.88` |
| `INC-0015` | **CRITICAL** | Massive S3 Data Exfiltration | `T1530 - Data from Cloud Storage` | `unknown_user` | `203.0.113.88` |
| `INC-0016` | **CRITICAL** | Massive S3 Data Exfiltration | `T1530 - Data from Cloud Storage` | `unknown_user` | `203.0.113.88` |
| `INC-0017` | **CRITICAL** | Massive S3 Data Exfiltration | `T1530 - Data from Cloud Storage` | `unknown_user` | `203.0.113.88` |
| `INC-0018` | **CRITICAL** | Massive S3 Data Exfiltration | `T1530 - Data from Cloud Storage` | `unknown_user` | `203.0.113.88` |
| `INC-0019` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `123.98.150.36` |
| `INC-0020` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `shourya.tuhar` | `152.160.7.17` |
| `INC-0021` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `dev_service_account` | `162.3.29.117` |
| `INC-0022` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `admin` | `202.172.86.30` |
| `INC-0023` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `shourya.tuhar` | `86.3.94.220` |
| `INC-0024` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `110.18.63.223` |
| `INC-0025` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `185.220.101.5` |
| `INC-0026` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `185.220.101.5` |
| `INC-0027` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `mayank.sheoran` | `130.8.186.60` |
| `INC-0028` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `unknown_user` | `198.51.100.45` |
| `INC-0029` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `mayank.sheoran` | `61.244.135.128` |
| `INC-0030` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `mayank.sheoran` | `4.1.43.214` |
| `INC-0031` | **CRITICAL** | CloudTrail Defense Impairment / Tampering | `T1562.001 - Impair Defenses: Disable Cloud Logs` | `guest` | `8.47.6.185` |
| `INC-0032` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `124.220.123.53` |
| `INC-0033` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `9.116.93.109` |
| `INC-0034` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `181.27.237.216` |
| `INC-0035` | **CRITICAL** | AWS Root Account Activity Detected | `T1078.001 - Valid Accounts: Default Accounts` | `root` | `87.59.19.173` |
| `INC-0036` | **HIGH** | Unauthorized IAM Privilege Escalation | `T1098 - Account Manipulation` | `guest` | `198.51.100.45` |
| `INC-0037` | **HIGH** | Mass S3 Resource Deletion Activity | `T1485 - Data Destruction` | `mandeep.singh` | `129.153.198.180` |
| `INC-0038` | **HIGH** | Mass S3 Resource Deletion Activity | `T1485 - Data Destruction` | `unknown_user` | `203.0.113.88` |
| `INC-0039` | **HIGH** | Unauthorized IAM Privilege Escalation | `T1098 - Account Manipulation` | `manan.gupta` | `116.115.120.25` |
| `INC-0040` | **HIGH** | Impossible Travel / Geolocation Anomaly | `T1078 - Valid Accounts` | `shourya.tuhar` | `103.21.244.10 -> 185.220.101.5` |
| `INC-0041` | **HIGH** | Unauthorized IAM Privilege Escalation | `T1098 - Account Manipulation` | `dev_service_account` | `199.191.48.248` |
| `INC-0042` | **HIGH** | Unauthorized IAM Privilege Escalation | `T1098 - Account Manipulation` | `guest` | `61.4.172.164` |
| `INC-0043` | **HIGH** | Unauthorized IAM Privilege Escalation | `T1098 - Account Manipulation` | `mandeep.singh` | `189.181.186.216` |
| `INC-0044` | **HIGH** | Unauthorized IAM Privilege Escalation | `T1098 - Account Manipulation` | `root` | `87.59.19.173` |

---

## 2. CIS AWS Foundations Benchmark Audit
| Control ID | Benchmark Control | Status | Severity | Remediation Summary |
|---|---|---|---|---|
| `CIS-1.1` | Avoid Root Account Usage | ❌ **FAILED** | CRITICAL | Lock root account credentials in a secure vault, enable hardware MFA, and provision least-privilege IAM roles. |
| `CIS-1.16` | Ensure IAM Policies Are Attached Only to Groups/Roles | ❌ **FAILED** | HIGH | Attach permissions policies exclusively to IAM groups or IAM roles to prevent permission drift. |
| `CIS-1.4` | Access Key Lifecycle Monitoring | ❌ **FAILED** | MEDIUM | Verify business justification for permanent programmatic keys and audit IAM user permissions. |
| `CIS-3.1` | Unauthorized API Calls Monitoring | ❌ **FAILED** | HIGH | Set up CloudWatch Alarms to immediately notify security operations whenever unauthorized API calls spike. |
| `CIS-3.2` | MFA Enforcement for Console Logins | ❌ **FAILED** | HIGH | Apply an IAM boundary policy that denies all console actions unless `aws:MultiFactorAuthPresent` is true. |
| `CIS-3.3` | Continuous CloudTrail Logging & Tamper Resistance | ❌ **FAILED** | CRITICAL | Enforce AWS Organizations Service Control Policies (SCPs) denying `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail`. |
| `CIS-2.1` | S3 Bucket & Object Protection | ❌ **WARNING** | MEDIUM | Enable S3 Object Lock in Compliance mode and require MFA Delete for bucket configuration changes. |
