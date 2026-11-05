#!/usr/bin/env python3
"""
Security Log Analyzer  (CodeNova Cybersecurity - Task 4)

Parses Linux auth.log (sshd) or Apache/Nginx access logs, groups failed logins
by source IP, detects anomalies (off-hours access, rapid sequential attempts,
known attack signatures, success-after-failures) and writes a Markdown/TXT
security incident report with tables and severity flags.

Usage:
    python log_analyzer.py sample_auth.log -o security_report.md
    python log_analyzer.py sample_access.log --format web --threshold 5
    python log_analyzer.py auth.log --year 2026 --business-hours 8 20 --burst 5 60

ONLY use on sanitized / synthetic / your own logs.
"""
import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

try:  # optional, nicer tables if installed; built-in renderer is the fallback
    from tabulate import tabulate as _tabulate
except ImportError:
    _tabulate = None

# ---------------------------------------------------------------- regexes
MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
SYSLOG_RE = re.compile(rf"^(?P<mon>{MONTHS})\s+(?P<day>\d{{1,2}})\s+(?P<time>\d{{2}}:\d{{2}}:\d{{2}})\s+\S+\s+(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
FAILED_RE = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)")
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)")
ACCEPT_RE = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)")
REPEAT_RE = re.compile(r"message repeated (?P<n>\d+) times: \[ (?P<inner>.*)\]")
BREAKIN_RE = re.compile(r"POSSIBLE BREAK-IN ATTEMPT")
WEB_RE = re.compile(r'^(?P<ip>[\da-fA-F:.]+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?')

# ---------------------------------------------------------------- signatures
SUSPICIOUS_USERS = {"root", "admin", "administrator", "test", "oracle", "postgres",
                    "ubuntu", "guest", "user", "pi", "ftpuser", "support", "mysql", "git"}
WEB_SIGNATURES = [
    (re.compile(r"\.\./|%2e%2e", re.I), "Path traversal"),
    (re.compile(r"union(\+|%20|\s)+select|or\s*1=1|'--", re.I), "SQL injection"),
    (re.compile(r"/\.env|/\.git/|/etc/passwd", re.I), "Sensitive file probe"),
    (re.compile(r"phpmyadmin|wp-login|xmlrpc\.php", re.I), "Admin panel probe"),
    (re.compile(r"sqlmap|nikto|nmap|masscan|hydra|dirbuster", re.I), "Attack tool user-agent"),
]
LOGIN_PATH_RE = re.compile(r"login|signin|auth|wp-login|admin", re.I)
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Event:
    ts: datetime
    ip: str
    user: str
    kind: str            # "fail" | "success" | "info"
    signature: str = ""  # known attack signature label, if any
    raw: str = ""


@dataclass
class IPStats:
    ip: str
    failures: int = 0
    successes: int = 0
    users: set = field(default_factory=set)
    fail_times: list = field(default_factory=list)
    off_hours: int = 0
    signatures: set = field(default_factory=set)
    success_after_fail: bool = False
    max_burst: int = 0
    first: datetime = None
    last: datetime = None


# ---------------------------------------------------------------- parsing
def parse_auth_line(line, year):
    m = SYSLOG_RE.match(line)
    if not m:
        return []
    try:
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return []
    msg = m["msg"]
    rep = REPEAT_RE.search(msg)
    count = 1
    if rep:
        count, msg = int(rep["n"]), rep["inner"]
    if (f := FAILED_RE.search(msg)):
        sig = "Known attack username" if f["user"].lower() in SUSPICIOUS_USERS else ""
        return [Event(ts, f["ip"], f["user"], "fail", sig, line)] * count
    if (a := ACCEPT_RE.search(msg)):
        return [Event(ts, a["ip"], a["user"], "success", "", line)]
    if (i := INVALID_RE.search(msg)):  # enumeration hint, counted as an info event
        sig = "Known attack username" if i["user"].lower() in SUSPICIOUS_USERS else ""
        return [Event(ts, i["ip"], i["user"], "info", sig, line)]
    if BREAKIN_RE.search(msg):
        return [Event(ts, "-", "-", "info", "Reverse-DNS mismatch (POSSIBLE BREAK-IN ATTEMPT)", line)]
    return []


def parse_web_line(line, _year=None):
    m = WEB_RE.match(line)
    if not m:
        return []
    try:
        ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return []
    path, status, ua = m["path"], int(m["status"]), m["ua"] or ""
    sigs = [label for rx, label in WEB_SIGNATURES if rx.search(path) or rx.search(ua)]
    sig = ", ".join(sigs)
    if status in (401, 403) and (LOGIN_PATH_RE.search(path) or status == 401):
        return [Event(ts, m["ip"], "-", "fail", sig, line)]
    if status == 200 and m["method"] == "POST" and LOGIN_PATH_RE.search(path):
        return [Event(ts, m["ip"], "-", "success", sig, line)]
    if sig:
        return [Event(ts, m["ip"], "-", "info", sig, line)]
    return []


def detect_format(path: Path) -> str:
    with open(path, errors="replace") as f:
        for _, line in zip(range(25), f):
            if WEB_RE.match(line):
                return "web"
            if SYSLOG_RE.match(line):
                return "auth"
    return "auth"


def load_events(path: Path, fmt: str, year: int):
    parser = parse_web_line if fmt == "web" else parse_auth_line
    events, skipped, total = [], 0, 0
    with open(path, errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            total += 1
            evs = parser(line, year)
            if evs:
                events.extend(evs)
            else:
                skipped += 1
    return events, total, skipped


# ---------------------------------------------------------------- analysis
def max_burst(times, window_s):
    """Largest number of failures falling in any sliding `window_s` second window."""
    times = sorted(times)
    best, lo = 0, 0
    for hi, t in enumerate(times):
        while (t - times[lo]).total_seconds() > window_s:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def is_off_hours(ts, start, end):
    return not (start <= ts.hour < end)


def analyze(events, args):
    stats = {}
    for ev in sorted(events, key=lambda e: e.ts):
        if ev.ip == "-":
            continue
        s = stats.setdefault(ev.ip, IPStats(ev.ip))
        s.first = s.first or ev.ts
        s.last = ev.ts
        if ev.signature:
            s.signatures.update(x.strip() for x in ev.signature.split(","))
        if ev.kind == "fail":
            s.failures += 1
            s.users.add(ev.user)
            s.fail_times.append(ev.ts)
            if is_off_hours(ev.ts, *args.business_hours):
                s.off_hours += 1
        elif ev.kind == "success":
            s.successes += 1
            if s.failures >= args.threshold:
                s.success_after_fail = True
            if is_off_hours(ev.ts, *args.business_hours):
                s.off_hours += 1
                s.signatures.add("Off-hours successful login")
    incidents = []
    for s in stats.values():
        s.max_burst = max_burst(s.fail_times, args.burst_window) if s.fail_times else 0
        reasons, sev = [], None
        if s.success_after_fail:
            sev = "CRITICAL"
            reasons.append(f"SUCCESSFUL login after {s.failures} failures (possible compromise)")
        if s.failures >= args.brute_force or s.max_burst >= args.burst_count:
            sev = sev or "HIGH"
            reasons.append(f"Brute-force pattern: {s.failures} failures, peak {s.max_burst} in {args.burst_window}s")
        if len(s.users) >= 5:
            sev = sev or "HIGH"
            reasons.append(f"Username enumeration: {len(s.users)} distinct usernames tried")
        if s.failures >= args.threshold:
            sev = sev or "MEDIUM"
            reasons.append(f"Failed-login threshold exceeded ({s.failures} >= {args.threshold})")
        if s.off_hours and (s.failures or "Off-hours successful login" in s.signatures):
            reasons.append(f"{s.off_hours} event(s) outside business hours")
            sev = sev or "MEDIUM"
        known = sorted(x for x in s.signatures if x != "Off-hours successful login")
        if known:
            reasons.append("Signatures: " + ", ".join(known))
            sev = sev or "MEDIUM"
        if sev is None and s.failures:
            sev, reasons = "LOW", ["Routine failed login(s), below threshold"]
        if sev:
            incidents.append((sev, s, reasons))
    incidents.sort(key=lambda x: (SEV_ORDER[x[0]], -x[1].failures))
    return stats, incidents


# ---------------------------------------------------------------- report
def table(rows, headers):
    """Markdown table (uses tabulate if available, otherwise built-in)."""
    if _tabulate:
        return _tabulate(rows, headers=headers, tablefmt="github")
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "/") for c in r) + " |")
    return "\n".join(out)


BADGE = {"CRITICAL": "🔴 CRITICAL", "HIGH": "🟠 HIGH", "MEDIUM": "🟡 MEDIUM", "LOW": "🟢 LOW"}


def build_report(src, fmt, total, skipped, events, stats, incidents, args):
    fails = [e for e in events if e.kind == "fail"]
    sev_count = {k: sum(1 for i in incidents if i[0] == k) for k in SEV_ORDER}
    attacks = [i for i in incidents if i[0] in ("CRITICAL", "HIGH")]
    routine = [i for i in incidents if i[0] == "LOW"]
    L = []
    L.append("# Security Incident Report\n")
    L.append(f"- **Source log:** `{src.name}` ({'Apache/Nginx access log' if fmt == 'web' else 'Linux auth.log (sshd)'})")
    L.append(f"- **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"- **Lines read:** {total} (parsed as security events: {total - skipped}, ignored: {skipped})")
    L.append(f"- **Settings:** failed-login threshold = {args.threshold}, brute-force >= {args.brute_force} failures, "
             f"burst = {args.burst_count} failures in {args.burst_window}s, business hours = {args.business_hours[0]:02d}:00-{args.business_hours[1]:02d}:00")
    L.append("- **Data note:** analysis of sanitized / synthetic logs only\n")

    L.append("## 1. Executive Summary\n")
    L.append(table([
        ["Total failed login attempts", len(fails)],
        ["Unique source IPs with failures", sum(1 for s in stats.values() if s.failures)],
        ["🔴 CRITICAL incidents", sev_count["CRITICAL"]],
        ["🟠 HIGH incidents (brute force)", sev_count["HIGH"]],
        ["🟡 MEDIUM incidents", sev_count["MEDIUM"]],
        ["🟢 LOW (routine errors)", sev_count["LOW"]],
    ], ["Metric", "Value"]) + "\n")

    L.append("## 2. Failed Login Attempts by Source IP\n")
    rows = []
    for s in sorted(stats.values(), key=lambda x: -x.failures):
        if not s.failures:
            continue
        flag = "YES" if s.failures >= args.threshold else "no"
        rows.append([s.ip, s.failures, len(s.users), s.max_burst, s.successes, flag,
                     s.first.strftime("%m-%d %H:%M:%S"), s.last.strftime("%m-%d %H:%M:%S")])
    L.append(table(rows, ["Source IP", "Failed", "Distinct users", f"Peak/{args.burst_window}s",
                          "Successes", f"Threshold (>={args.threshold})", "First seen", "Last seen"]) + "\n")

    L.append("## 3. Incident Table (with Severity Flags)\n")
    L.append(table([[BADGE[sev], s.ip, s.failures, "; ".join(r)] for sev, s, r in incidents],
                   ["Severity", "Source IP", "Failures", "Findings"]) + "\n")

    L.append("## 4. Detected Anomalies\n")
    L.append("### 4.1 High-volume brute-force attacks (HIGH / CRITICAL)\n")
    if attacks:
        for sev, s, r in attacks:
            L.append(f"- **{s.ip}** [{sev}] - {s.failures} failures against {len(s.users)} username(s) "
                     f"({', '.join(sorted(s.users)[:8])}{'...' if len(s.users) > 8 else ''}); "
                     f"active {s.first.strftime('%H:%M:%S')} to {s.last.strftime('%H:%M:%S')}")
    else:
        L.append("- None detected")
    L.append("\n### 4.2 Off-hours activity\n")
    off = [(s, s.off_hours) for s in stats.values() if s.off_hours]
    if off:
        L.append(table([[s.ip, n, s.failures, s.successes] for s, n in sorted(off, key=lambda x: -x[1])],
                       ["Source IP", "Off-hours events", "Failures", "Successes"]) + "\n")
    else:
        L.append("- None detected\n")
    L.append("### 4.3 Rapid sequential attempts\n")
    rapid = [s for s in stats.values() if s.max_burst >= args.burst_count]
    if rapid:
        for s in sorted(rapid, key=lambda x: -x.max_burst):
            L.append(f"- **{s.ip}**: {s.max_burst} failed attempts within {args.burst_window} seconds (automated tooling likely)")
    else:
        L.append("- None detected")
    L.append("\n### 4.4 Known attack signatures\n")
    sig_ips = [(s, sorted(x for x in s.signatures if x != 'Off-hours successful login')) for s in stats.values()]
    sig_ips = [(s, g) for s, g in sig_ips if g]
    if sig_ips:
        L.append(table([[s.ip, ", ".join(g)] for s, g in sig_ips], ["Source IP", "Signatures matched"]) + "\n")
    else:
        L.append("- None detected\n")

    L.append("## 5. Routine Errors vs. Brute-Force Attacks\n")
    L.append("| Category | Definition | IPs |\n|---|---|---|")
    L.append(f"| Routine login errors | below {args.threshold} failures, no anomalies (typos, forgotten passwords) | "
             f"{', '.join(s.ip for _, s, _ in routine) or '-'} |")
    L.append(f"| Threshold violations | {args.threshold}+ failures but below brute-force volume | "
             f"{', '.join(s.ip for sev, s, _ in incidents if sev == 'MEDIUM' and s.failures >= args.threshold) or '-'} |")
    L.append(f"| High-volume brute force | {args.brute_force}+ failures or {args.burst_count}+ in {args.burst_window}s or 5+ usernames | "
             f"{', '.join(s.ip for sev, s, _ in incidents if sev in ('HIGH', 'CRITICAL')) or '-'} |\n")

    L.append("## 6. Recommended Actions\n")
    for sev, s, _ in incidents:
        if sev == "CRITICAL":
            L.append(f"1. **{s.ip}**: treat host as compromised - block IP, force password reset for targeted accounts, review session activity, rotate credentials.")
        elif sev == "HIGH":
            L.append(f"1. **{s.ip}**: block at firewall / add to fail2ban, enforce key-only SSH, disable password auth.")
        elif sev == "MEDIUM":
            L.append(f"1. **{s.ip}**: monitor and rate-limit; confirm whether off-hours access was authorised.")
    L.append("1. Enable fail2ban or account lockout, MFA, and disable direct root SSH login.\n")
    return "\n".join(L)


def main():
    p = argparse.ArgumentParser(description="Security log analyzer")
    p.add_argument("logfile", type=Path)
    p.add_argument("-o", "--output", type=Path, default=Path("security_report.md"), help=".md or .txt report path")
    p.add_argument("--format", choices=["auto", "auth", "web"], default="auto")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog timestamps (they carry none)")
    p.add_argument("--threshold", type=int, default=5, help="failed attempts per IP that counts as a violation")
    p.add_argument("--brute-force", type=int, default=20, help="failures per IP considered a brute-force attack")
    p.add_argument("--burst", nargs=2, type=int, metavar=("COUNT", "SECONDS"), default=[5, 60],
                   help="N failures within S seconds = rapid sequential attempts")
    p.add_argument("--business-hours", nargs=2, type=int, metavar=("START", "END"), default=[8, 20])
    args = p.parse_args()
    args.burst_count, args.burst_window = args.burst
    if not args.logfile.is_file():
        print(f"[!] Log file not found: {args.logfile}", file=sys.stderr)
        return 2
    fmt = detect_format(args.logfile) if args.format == "auto" else args.format
    events, total, skipped = load_events(args.logfile, fmt, args.year)
    if not events:
        print("[!] No recognisable security events found.", file=sys.stderr)
        return 2
    stats, incidents = analyze(events, args)
    report = build_report(args.logfile, fmt, total, skipped, events, stats, incidents, args)
    args.output.write_text(report, encoding="utf-8")
    print(f"[+] {fmt} log analysed: {total} lines, {len(events)} events, {len(incidents)} incidents flagged")
    for sev, s, _ in incidents:
        print(f"    {sev:<8} {s.ip:<16} failures={s.failures}")
    print(f"[+] Report written: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
