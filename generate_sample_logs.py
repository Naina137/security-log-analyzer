#!/usr/bin/env python3
"""Generates SYNTHETIC log files for testing (fixed seed = reproducible).
All IPs come from the documentation ranges (RFC 5737) and all names are fake."""
import random
from datetime import datetime, timedelta

random.seed(42)
HOST = "web01"
YEAR = 2026
lines = []  # (datetime, text)


def sshd(ts, msg):
    pid = random.randint(1000, 9999)
    lines.append((ts, f"{ts.strftime('%b %e %H:%M:%S')} {HOST} sshd[{pid}]: {msg}"))


base = datetime(YEAR, 11, 3, 0, 0, 0)

# 1) Normal staff activity during working hours
for user, ip, hour in [("alice", "192.0.2.10", 9), ("bob", "192.0.2.11", 10),
                       ("carol", "192.0.2.12", 11), ("alice", "192.0.2.10", 14),
                       ("dave", "192.0.2.13", 15), ("bob", "192.0.2.11", 17)]:
    ts = base + timedelta(hours=hour, minutes=random.randint(0, 59), seconds=random.randint(0, 59))
    sshd(ts, f"Accepted publickey for {user} from {ip} port {random.randint(40000, 60000)} ssh2")

# 2) Routine failures: staff mistyping passwords (LOW severity)
for user, ip, hour in [("alice", "192.0.2.10", 9), ("carol", "192.0.2.12", 11), ("erin", "192.0.2.14", 13)]:
    ts = base + timedelta(hours=hour, minutes=random.randint(0, 59))
    for k in range(random.randint(1, 2)):
        sshd(ts + timedelta(seconds=20 * k), f"Failed password for {user} from {ip} port {random.randint(40000, 60000)} ssh2")

# 3) Brute force attack: fast, sequential, many usernames, off-hours (02:14 AM)
ts = base + timedelta(hours=2, minutes=14, seconds=7)
users = ["root", "admin", "test", "oracle", "postgres", "ubuntu", "guest", "user", "pi", "ftpuser"]
for i in range(48):
    u = users[i % len(users)]
    inv = "invalid user " if u not in ("root",) else ""
    sshd(ts, f"Failed password for {inv}{u} from 203.0.113.45 port {random.randint(30000, 65000)} ssh2")
    if i % 7 == 0:
        sshd(ts, f"Invalid user {u} from 203.0.113.45 port {random.randint(30000, 65000)}")
    ts += timedelta(seconds=random.choice([1, 1, 2]))
sshd(ts, "message repeated 5 times: [ Failed password for root from 203.0.113.45 port 41022 ssh2]")

# 4) Successful break-in after brute force (CRITICAL): attacker 198.51.100.77
ts = base + timedelta(hours=3, minutes=41, seconds=2)
for i in range(14):
    sshd(ts, f"Failed password for admin from 198.51.100.77 port {random.randint(30000, 65000)} ssh2")
    ts += timedelta(seconds=2)
sshd(ts, f"Accepted password for admin from 198.51.100.77 port {random.randint(30000, 65000)} ssh2")

# 5) Slow, low-volume scanner: moderate failures (threshold violation, medium)
ts = base + timedelta(hours=16, minutes=5)
for i in range(7):
    sshd(ts, f"Failed password for invalid user support from 203.0.113.99 port {random.randint(30000, 65000)} ssh2")
    ts += timedelta(minutes=random.randint(3, 9))

# 6) Off-hours legit-looking login (flag for review)
sshd(base + timedelta(hours=23, minutes=52, seconds=30),
     "Accepted publickey for dave from 192.0.2.13 port 51022 ssh2")

# 7) Misc noise
sshd(base + timedelta(hours=12), "Server listening on 0.0.0.0 port 22.")
sshd(base + timedelta(hours=12, minutes=30), "Received disconnect from 192.0.2.10 port 50011:11: disconnected by user")
sshd(base + timedelta(hours=6, minutes=3),
     "reverse mapping checking getaddrinfo for host-203-0-113-45.example failed - POSSIBLE BREAK-IN ATTEMPT!")

lines.sort(key=lambda x: x[0])
with open("sample_auth.log", "w") as f:
    f.write("\n".join(t for _, t in lines) + "\n")

# ---- Apache/Nginx combined-format sample --------------------------------
web = []


def acc(ts, ip, method, path, status, size, ua="Mozilla/5.0"):
    web.append((ts, f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'))


t = datetime(YEAR, 11, 3, 9, 0, 0)
for p in ["/", "/about", "/products", "/contact", "/login"]:
    acc(t, "192.0.2.10", "GET", p, 200, 2048); t += timedelta(minutes=2)
acc(t, "192.0.2.11", "POST", "/login", 401, 120); t += timedelta(seconds=30)
acc(t, "192.0.2.11", "POST", "/login", 200, 512)
t = datetime(YEAR, 11, 3, 1, 30, 0)
for i in range(30):
    acc(t, "203.0.113.45", "POST", "/wp-login.php", 401, 120, "python-requests/2.31"); t += timedelta(seconds=1)
for p in ["/.env", "/phpmyadmin/", "/../../etc/passwd", "/search?q=1'+UNION+SELECT+1,2--"]:
    acc(t, "198.51.100.77", "GET", p, 404, 150, "sqlmap/1.7"); t += timedelta(seconds=1)
web.sort(key=lambda x: x[0])
with open("sample_access.log", "w") as f:
    f.write("\n".join(x for _, x in web) + "\n")
print("sample_auth.log and sample_access.log generated")
