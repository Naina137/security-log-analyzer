<div align="center">

# 🛡️ Security Log Analyzer

### Failed-Login Detection • Brute-Force Alerts • Incident Report

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Logs](https://img.shields.io/badge/Logs-auth.log%20%7C%20Apache%20%7C%20Nginx-informational)
![Tests](https://img.shields.io/badge/Tests-6%20passing-brightgreen)
![Severity](https://img.shields.io/badge/Severity-CRITICAL%20%7C%20HIGH%20%7C%20MEDIUM%20%7C%20LOW-red)
![CodeNova](https://img.shields.io/badge/CodeNova-Cybersecurity%20Batch%2001-orange)

**Task 4 | CodeNova Internship Program | Incident Response & Anomaly Detection**

</div>

---

> ⚠️ Works **only on sanitized / synthetic logs**. All sample IPs are from reserved documentation ranges (RFC 5737) and all usernames are fictional.

## 🎯 What it does

Reads **Linux auth.log** or **Apache/Nginx access logs**, counts **failed logins per IP**, detects anomalies and
writes a structured **Security Incident Report** with tables and severity flags.

## ✨ Features

-  Parses sshd `auth.log` and web access logs (`--format auto|auth|web`) using **Regex** + **Datetime**
-  Failed attempts **grouped by source IP** with configurable threshold (default 5)
- **Off-hours access** detection (default business hours 08:00 to 20:00)
-  **Rapid sequential attempts** (5+ failures in 60 s sliding window)
-  **Known attack signatures**: root/admin/oracle usernames, path traversal, SQL injection, `/.env` probes, sqlmap/nikto user-agents
-  Username enumeration and **success-after-failures** (possible compromise)
-  Report separates **routine login errors** from **high-volume brute-force attacks**

## 🚦 Severity Levels

| Level | Trigger |
|---|---|
| 🔴 **CRITICAL** | successful login after failures reached the threshold (possible compromise) |
| 🟠 **HIGH** | 20+ failures, or 5+ in 60 s, or 5+ distinct usernames |
| 🟡 **MEDIUM** | threshold exceeded, off-hours activity, or attack signature |
| 🟢 **LOW** | routine failures below threshold (typos) |

## 🚀 Quick Start

```bash
# (optional) regenerate synthetic logs
python generate_sample_logs.py

# analyse the SSH log
python log_analyzer.py sample_auth.log --year 2026 -o security_report.md

# analyse the web-server log
python log_analyzer.py sample_access.log --year 2026 -o security_report_web.md

# custom thresholds
python log_analyzer.py sample_auth.log --threshold 3 --brute-force 15 --burst 5 30 --business-hours 9 18

# run tests
python -m unittest -v test_log_analyzer
```

| Option | Default | Meaning |
|---|---|---|
| `--threshold` | 5 | failures per IP = threshold violation |
| `--brute-force` | 20 | failures per IP = brute-force attack |
| `--burst COUNT SECONDS` | 5 60 | rapid-attempt window |
| `--business-hours START END` | 8 20 | outside = off-hours |
| `--year` | current | syslog lines have no year |

## 🧪 Test Scenarios (planted in the synthetic log)

| Scenario | IP | Result |
|---|---|---|
| 02:14 AM dictionary attack, 10 usernames | 203.0.113.45 | 🟠 HIGH |
| 14 rapid failures then successful login | 198.51.100.77 | 🔴 CRITICAL |
| Slow scanner, 7 failures | 203.0.113.99 | 🟡 MEDIUM |
| Staff typos, 1 to 2 failures | 192.0.2.10 / .12 / .14 | 🟢 LOW |
| Legit login at 23:52 | 192.0.2.13 | 🟡 MEDIUM (review) |

## 📄 Generated Report (`security_report.md`)


- **Source log:** `sample_auth.log` (Linux auth.log (sshd))
- **Generated:** 2026-11-05 15:03:04
- **Lines read:** 93 (parsed as security events: 91, ignored: 2)
- **Settings:** failed-login threshold = 5, brute-force >= 20 failures, burst = 5 failures in 60s, business hours = 08:00-20:00
- **Data note:** analysis of sanitized / synthetic logs only

## 1. Executive Summary

| Metric                          |   Value |
|---------------------------------|---------|
| Total failed login attempts     |      79 |
| Unique source IPs with failures |       6 |
| 🔴 CRITICAL incidents            |       1 |
| 🟠 HIGH incidents (brute force)  |       1 |
| 🟡 MEDIUM incidents              |       2 |
| 🟢 LOW (routine errors)          |       3 |

## 2. Failed Login Attempts by Source IP

| Source IP     |   Failed |   Distinct users |   Peak/60s |   Successes | Threshold (>=5)   | First seen     | Last seen      |
|---------------|----------|------------------|------------|-------------|-------------------|----------------|----------------|
| 203.0.113.45  |       53 |               10 |         44 |           0 | YES               | 11-03 02:14:07 | 11-03 02:15:19 |
| 198.51.100.77 |       14 |                1 |         14 |           1 | YES               | 11-03 03:41:02 | 11-03 03:41:30 |
| 203.0.113.99  |        7 |                1 |          1 |           0 | YES               | 11-03 16:05:00 | 11-03 16:40:00 |
| 192.0.2.10    |        2 |                1 |          2 |           2 | no                | 11-03 09:40:07 | 11-03 14:37:27 |
| 192.0.2.14    |        2 |                1 |          2 |           0 | no                | 11-03 13:21:00 | 11-03 13:21:20 |
| 192.0.2.12    |        1 |                1 |          1 |           1 | no                | 11-03 11:43:47 | 11-03 11:51:00 |

## 3. Incident Table (with Severity Flags)

| Severity   | Source IP     |   Failures | Findings                                                                                                                                                                                                                     |
|------------|---------------|------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 🔴 CRITICAL | 198.51.100.77 |         14 | SUCCESSFUL login after 14 failures (possible compromise); Brute-force pattern: 14 failures, peak 14 in 60s; Failed-login threshold exceeded (14 >= 5); 15 event(s) outside business hours; Signatures: Known attack username |
| 🟠 HIGH     | 203.0.113.45  |         53 | Brute-force pattern: 53 failures, peak 44 in 60s; Username enumeration: 10 distinct usernames tried; Failed-login threshold exceeded (53 >= 5); 53 event(s) outside business hours; Signatures: Known attack username        |
| 🟡 MEDIUM   | 203.0.113.99  |          7 | Failed-login threshold exceeded (7 >= 5); Signatures: Known attack username                                                                                                                                                  |
| 🟡 MEDIUM   | 192.0.2.13    |          0 | 1 event(s) outside business hours                                                                                                                                                                                            |
| 🟢 LOW      | 192.0.2.10    |          2 | Routine failed login(s), below threshold                                                                                                                                                                                     |
| 🟢 LOW      | 192.0.2.14    |          2 | Routine failed login(s), below threshold                                                                                                                                                                                     |
| 🟢 LOW      | 192.0.2.12    |          1 | Routine failed login(s), below threshold                                                                                                                                                                                     |

## 4. Detected Anomalies

### 4.1 High-volume brute-force attacks (HIGH / CRITICAL)

- **198.51.100.77** [CRITICAL] - 14 failures against 1 username(s) (admin); active 03:41:02 to 03:41:30
- **203.0.113.45** [HIGH] - 53 failures against 10 username(s) (admin, ftpuser, guest, oracle, pi, postgres, root, test...); active 02:14:07 to 02:15:19

### 4.2 Off-hours activity

| Source IP     |   Off-hours events |   Failures |   Successes |
|---------------|--------------------|------------|-------------|
| 203.0.113.45  |                 53 |         53 |           0 |
| 198.51.100.77 |                 15 |         14 |           1 |
| 192.0.2.13    |                  1 |          0 |           2 |

### 4.3 Rapid sequential attempts

- **203.0.113.45**: 44 failed attempts within 60 seconds (automated tooling likely)
- **198.51.100.77**: 14 failed attempts within 60 seconds (automated tooling likely)

### 4.4 Known attack signatures

| Source IP     | Signatures matched    |
|---------------|-----------------------|
| 203.0.113.45  | Known attack username |
| 198.51.100.77 | Known attack username |
| 203.0.113.99  | Known attack username |

## 5. Routine Errors vs. Brute-Force Attacks

| Category | Definition | IPs |
|---|---|---|
| Routine login errors | below 5 failures, no anomalies (typos, forgotten passwords) | 192.0.2.10, 192.0.2.14, 192.0.2.12 |
| Threshold violations | 5+ failures but below brute-force volume | 203.0.113.99 |
| High-volume brute force | 20+ failures or 5+ in 60s or 5+ usernames | 198.51.100.77, 203.0.113.45 |

## 6. Recommended Actions

1. **198.51.100.77**: treat host as compromised - block IP, force password reset for targeted accounts, review session activity, rotate credentials.
1. **203.0.113.45**: block at firewall / add to fail2ban, enforce key-only SSH, disable password auth.
1. **203.0.113.99**: monitor and rate-limit; confirm whether off-hours access was authorised.
1. **192.0.2.13**: monitor and rate-limit; confirm whether off-hours access was authorised.
1. Enable fail2ban or account lockout, MFA, and disable direct root SSH login.


*Web-server log report: `security_report_web.md`.*

## 📂 Project Structure

```
task4_security_log_analyzer/
├── log_analyzer.py            # analyzer script
├── generate_sample_logs.py    # synthetic log generator
├── sample_auth.log            # sanitized server log (sshd)
├── sample_access.log          # sanitized web log
├── security_report.md         # generated incident report
├── security_report_web.md     # generated web report
├── test_log_analyzer.py       # unit tests
└── README.md
```

## ✅ Acceptance Criteria

| Criterion | Status |
|---|---|
| Works exclusively on sanitized / synthetic logs | ✅ |
| Accurately tallies failed attempts per IP and flags threshold violations | ✅ |
| Differentiates routine errors from high-volume brute force | ✅ |
| Log analyzer script, test log, generated incident report | ✅ |

## 🔭 Future Work

GeoIP enrichment, JSON output, live log tailing, fail2ban rule export.

---

<div align="center">Made by <b>Naina Kumari</b> | CodeNova Cybersecurity Internship, Batch 01</div>
