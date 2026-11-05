# Security Incident Report

- **Source log:** `sample_auth.log` (Linux auth.log (sshd))
- **Generated:** 2026-11-06 02:01:49
- **Lines read:** 93 (parsed as security events: 91, ignored: 2)
- **Settings:** failed-login threshold = 5, brute-force >= 20 failures, burst = 5 failures in 60s, business hours = 08:00-20:00
- **Data note:** analysis of sanitized / synthetic logs only

## 1. Executive Summary

| Metric | Value |
|---|---|
| Total failed login attempts | 79 |
| Unique source IPs with failures | 6 |
| 🔴 CRITICAL incidents | 1 |
| 🟠 HIGH incidents (brute force) | 1 |
| 🟡 MEDIUM incidents | 2 |
| 🟢 LOW (routine errors) | 3 |

## 2. Failed Login Attempts by Source IP

| Source IP | Failed | Distinct users | Peak/60s | Successes | Threshold (>=5) | First seen | Last seen |
|---|---|---|---|---|---|---|---|
| 203.0.113.45 | 53 | 10 | 44 | 0 | YES | 11-03 02:14:07 | 11-03 02:15:19 |
| 198.51.100.77 | 14 | 1 | 14 | 1 | YES | 11-03 03:41:02 | 11-03 03:41:30 |
| 203.0.113.99 | 7 | 1 | 1 | 0 | YES | 11-03 16:05:00 | 11-03 16:40:00 |
| 192.0.2.10 | 2 | 1 | 2 | 2 | no | 11-03 09:40:07 | 11-03 14:37:27 |
| 192.0.2.14 | 2 | 1 | 2 | 0 | no | 11-03 13:21:00 | 11-03 13:21:20 |
| 192.0.2.12 | 1 | 1 | 1 | 1 | no | 11-03 11:43:47 | 11-03 11:51:00 |

## 3. Incident Table (with Severity Flags)

| Severity | Source IP | Failures | Findings |
|---|---|---|---|
| 🔴 CRITICAL | 198.51.100.77 | 14 | SUCCESSFUL login after 14 failures (possible compromise); Brute-force pattern: 14 failures, peak 14 in 60s; Failed-login threshold exceeded (14 >= 5); 15 event(s) outside business hours; Signatures: Known attack username |
| 🟠 HIGH | 203.0.113.45 | 53 | Brute-force pattern: 53 failures, peak 44 in 60s; Username enumeration: 10 distinct usernames tried; Failed-login threshold exceeded (53 >= 5); 53 event(s) outside business hours; Signatures: Known attack username |
| 🟡 MEDIUM | 203.0.113.99 | 7 | Failed-login threshold exceeded (7 >= 5); Signatures: Known attack username |
| 🟡 MEDIUM | 192.0.2.13 | 0 | 1 event(s) outside business hours |
| 🟢 LOW | 192.0.2.10 | 2 | Routine failed login(s), below threshold |
| 🟢 LOW | 192.0.2.14 | 2 | Routine failed login(s), below threshold |
| 🟢 LOW | 192.0.2.12 | 1 | Routine failed login(s), below threshold |

## 4. Detected Anomalies

### 4.1 High-volume brute-force attacks (HIGH / CRITICAL)

- **198.51.100.77** [CRITICAL] - 14 failures against 1 username(s) (admin); active 03:41:02 to 03:41:30
- **203.0.113.45** [HIGH] - 53 failures against 10 username(s) (admin, ftpuser, guest, oracle, pi, postgres, root, test...); active 02:14:07 to 02:15:19

### 4.2 Off-hours activity

| Source IP | Off-hours events | Failures | Successes |
|---|---|---|---|
| 203.0.113.45 | 53 | 53 | 0 |
| 198.51.100.77 | 15 | 14 | 1 |
| 192.0.2.13 | 1 | 0 | 2 |

### 4.3 Rapid sequential attempts

- **203.0.113.45**: 44 failed attempts within 60 seconds (automated tooling likely)
- **198.51.100.77**: 14 failed attempts within 60 seconds (automated tooling likely)

### 4.4 Known attack signatures

| Source IP | Signatures matched |
|---|---|
| 203.0.113.45 | Known attack username |
| 198.51.100.77 | Known attack username |
| 203.0.113.99 | Known attack username |

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
