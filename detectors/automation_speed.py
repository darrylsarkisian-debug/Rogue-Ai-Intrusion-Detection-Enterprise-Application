"""Goal 2: is someone attacking us with AI-speed automation?

We cannot prove an attacker is an AI. We detect behavior that is faster,
more uniform, or broader than a human, and report it as
"automation-like activity" with a confidence level.

Input auth log columns: ts, src_ip, user, result (success|fail)
Input flow log columns: ts, src_ip, dst_ip, dst_port
Rules:
  AUT-001  Machine-speed login attempts (many attempts, tiny uniform gaps)
  AUT-002  Password spray: one source, many distinct users, few tries each
  AUT-003  Wide-and-fast scan: one source, many dst ports or hosts in seconds
  AUT-004  Fail-then-success from an automation-like source (possible compromise)
"""
from __future__ import annotations

import pandas as pd

from .common import Finding, GOAL_AI_SPEED_ATTACK

MIN_ATTEMPTS = 20
MAX_MEDIAN_GAP_S = 1.0        # humans rarely sustain < 1s between logins
MAX_GAP_CV = 0.5              # coefficient of variation: low = very uniform
SPRAY_USERS = 10
SCAN_TARGETS = 50
SCAN_WINDOW_S = 60


def detect_auth(auth: pd.DataFrame) -> list[Finding]:
    findings: list[Finding] = []
    auth = auth.copy()
    auth["ts"] = pd.to_datetime(auth["ts"])
    for ip, g in auth.groupby("src_ip"):
        g = g.sort_values("ts")
        if len(g) < MIN_ATTEMPTS:
            continue
        gaps = g.ts.diff().dt.total_seconds().dropna()
        med, mean, std = gaps.median(), gaps.mean(), gaps.std()
        cv = (std / mean) if mean else 0.0
        fast = med <= MAX_MEDIAN_GAP_S
        uniform = cv <= MAX_GAP_CV
        users = g.user.nunique()
        conf = "high" if (fast and uniform) else "medium" if fast else "low"

        if fast:
            findings.append(Finding(
                GOAL_AI_SPEED_ATTACK, "AUT-001", "high", conf, ip,
                f"{ip} made {len(g)} login attempts with a median gap of "
                f"{med:.2f}s. Automation-like activity.",
                {"attempts": int(len(g)), "median_gap_s": round(float(med), 3),
                 "gap_cv": round(float(cv), 2), "distinct_users": int(users)}))
        if users >= SPRAY_USERS and (len(g) / users) <= 3:
            findings.append(Finding(
                GOAL_AI_SPEED_ATTACK, "AUT-002", "high", "high", ip,
                f"{ip} tried {users} different accounts about {len(g)/users:.1f} "
                "times each. Password-spray pattern.",
                {"distinct_users": int(users), "attempts": int(len(g))}))
        if fast and (g.result == "success").any() and (g.result == "fail").any():
            ok = g[g.result == "success"].iloc[0]
            findings.append(Finding(
                GOAL_AI_SPEED_ATTACK, "AUT-004", "critical", "medium", ip,
                f"{ip} succeeded as {ok.user} after a burst of failures. "
                "Treat that account as possibly compromised.",
                {"account": ok.user, "at": str(ok.ts)}))
    return findings


def detect_scan(flows: pd.DataFrame) -> list[Finding]:
    findings: list[Finding] = []
    flows = flows.copy()
    flows["ts"] = pd.to_datetime(flows["ts"])
    for ip, g in flows.groupby("src_ip"):
        g = g.sort_values("ts")
        span = (g.ts.max() - g.ts.min()).total_seconds()
        targets = g[["dst_ip", "dst_port"]].drop_duplicates()
        if len(targets) >= SCAN_TARGETS and span <= SCAN_WINDOW_S:
            findings.append(Finding(
                GOAL_AI_SPEED_ATTACK, "AUT-003", "high", "high", ip,
                f"{ip} touched {len(targets)} host/port pairs in {span:.0f}s. "
                "Wide-and-fast scanning.",
                {"targets": int(len(targets)), "seconds": round(span, 1),
                 "distinct_hosts": int(g.dst_ip.nunique()),
                 "distinct_ports": int(g.dst_port.nunique())}))
    return findings
