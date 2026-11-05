# Security Incident Report

- **Source log:** `sample_access.log` (Apache/Nginx access log)
- **Generated:** 2026-11-05 15:03:04
- **Lines read:** 41 (parsed as security events: 36, ignored: 5)
- **Settings:** failed-login threshold = 5, brute-force >= 20 failures, burst = 5 failures in 60s, business hours = 08:00-20:00
- **Data note:** analysis of sanitized / synthetic logs only

## 1. Executive Summary

| Metric                          |   Value |
|---------------------------------|---------|
| Total failed login attempts     |      31 |
| Unique source IPs with failures |       2 |
| 🔴 CRITICAL incidents            |       0 |
| 🟠 HIGH incidents (brute force)  |       1 |
| 🟡 MEDIUM incidents              |       1 |
| 🟢 LOW (routine errors)          |       1 |

## 2. Failed Login Attempts by Source IP

| Source IP    |   Failed |   Distinct users |   Peak/60s |   Successes | Threshold (>=5)   | First seen     | Last seen      |
|--------------|----------|------------------|------------|-------------|-------------------|----------------|----------------|
| 203.0.113.45 |       30 |                1 |         30 |           0 | YES               | 11-03 01:30:00 | 11-03 01:30:29 |
| 192.0.2.11   |        1 |                1 |          1 |           1 | no                | 11-03 09:10:00 | 11-03 09:10:30 |

## 3. Incident Table (with Severity Flags)

| Severity   | Source IP     |   Failures | Findings                                                                                                                                                       |
|------------|---------------|------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 🟠 HIGH     | 203.0.113.45  |         30 | Brute-force pattern: 30 failures, peak 30 in 60s; Failed-login threshold exceeded (30 >= 5); 30 event(s) outside business hours; Signatures: Admin panel probe |
| 🟡 MEDIUM   | 198.51.100.77 |          0 | Signatures: Admin panel probe, Attack tool user-agent, Path traversal, SQL injection, Sensitive file probe                                                     |
| 🟢 LOW      | 192.0.2.11    |          1 | Routine failed login(s), below threshold                                                                                                                       |

## 4. Detected Anomalies

### 4.1 High-volume brute-force attacks (HIGH / CRITICAL)

- **203.0.113.45** [HIGH] - 30 failures against 1 username(s) (-); active 01:30:00 to 01:30:29

### 4.2 Off-hours activity

| Source IP    |   Off-hours events |   Failures |   Successes |
|--------------|--------------------|------------|-------------|
| 203.0.113.45 |                 30 |         30 |           0 |

### 4.3 Rapid sequential attempts

- **203.0.113.45**: 30 failed attempts within 60 seconds (automated tooling likely)

### 4.4 Known attack signatures

| Source IP     | Signatures matched                                                                             |
|---------------|------------------------------------------------------------------------------------------------|
| 203.0.113.45  | Admin panel probe                                                                              |
| 198.51.100.77 | Admin panel probe, Attack tool user-agent, Path traversal, SQL injection, Sensitive file probe |

## 5. Routine Errors vs. Brute-Force Attacks

| Category | Definition | IPs |
|---|---|---|
| Routine login errors | below 5 failures, no anomalies (typos, forgotten passwords) | 192.0.2.11 |
| Threshold violations | 5+ failures but below brute-force volume | - |
| High-volume brute force | 20+ failures or 5+ in 60s or 5+ usernames | 203.0.113.45 |

## 6. Recommended Actions

1. **203.0.113.45**: block at firewall / add to fail2ban, enforce key-only SSH, disable password auth.
1. **198.51.100.77**: monitor and rate-limit; confirm whether off-hours access was authorised.
1. Enable fail2ban or account lockout, MFA, and disable direct root SSH login.
