import argparse, unittest
from datetime import datetime, timedelta
import log_analyzer as la

ARGS = argparse.Namespace(threshold=5, brute_force=20, burst_count=5, burst_window=60, business_hours=[8, 20])


def fail(ip, ts, user="bob"):
    return la.Event(ts, ip, user, "fail")


class AnalyzerTests(unittest.TestCase):
    def test_parse_failed_and_accepted(self):
        f = la.parse_auth_line("Nov  3 02:14:08 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.45 port 1 ssh2", 2026)
        a = la.parse_auth_line("Nov  3 09:00:00 web01 sshd[2]: Accepted publickey for alice from 192.0.2.10 port 2 ssh2", 2026)
        self.assertEqual((f[0].kind, f[0].ip, f[0].user), ("fail", "203.0.113.45", "admin"))
        self.assertEqual(a[0].kind, "success")

    def test_repeated_message_expands(self):
        e = la.parse_auth_line("Nov  3 02:00:00 h sshd[1]: message repeated 5 times: [ Failed password for root from 203.0.113.1 port 9 ssh2]", 2026)
        self.assertEqual(len(e), 5)

    def test_routine_vs_bruteforce(self):
        t = datetime(2026, 11, 3, 10, 0, 0)
        ev = [fail("192.0.2.1", t + timedelta(minutes=i * 10)) for i in range(2)]
        ev += [fail("203.0.113.5", t + timedelta(seconds=i)) for i in range(25)]
        _, inc = la.analyze(ev, ARGS)
        sev = {s.ip: v for v, s, _ in inc}
        self.assertEqual(sev["192.0.2.1"], "LOW")
        self.assertEqual(sev["203.0.113.5"], "HIGH")

    def test_threshold_boundary(self):
        t = datetime(2026, 11, 3, 10, 0, 0)
        ev4 = [fail("192.0.2.9", t + timedelta(minutes=i * 5)) for i in range(4)]
        ev5 = [fail("192.0.2.9", t + timedelta(minutes=i * 5)) for i in range(5)]
        self.assertEqual(la.analyze(ev4, ARGS)[1][0][0], "LOW")
        self.assertEqual(la.analyze(ev5, ARGS)[1][0][0], "MEDIUM")

    def test_success_after_failures_is_critical(self):
        t = datetime(2026, 11, 3, 10, 0, 0)
        ev = [fail("203.0.113.7", t + timedelta(minutes=i * 5)) for i in range(6)]
        ev.append(la.Event(t + timedelta(hours=1), "203.0.113.7", "bob", "success"))
        self.assertEqual(la.analyze(ev, ARGS)[1][0][0], "CRITICAL")

    def test_web_signatures(self):
        e = la.parse_web_line('198.51.100.7 - - [03/Nov/2026:01:30:00 +0000] "GET /../../etc/passwd HTTP/1.1" 404 1 "-" "sqlmap/1.7"')
        self.assertIn("Path traversal", e[0].signature)
        self.assertIn("Attack tool user-agent", e[0].signature)


if __name__ == "__main__":
    unittest.main()
