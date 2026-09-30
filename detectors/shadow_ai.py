"""Goal 1: are staff pasting company data into AI tools?

Input: proxy/DNS/firewall log rows with columns
  ts, src_ip, user, domain, method, bytes_out
Rules:
  SAI-001  Any visit to a known AI domain that is not sanctioned (visibility)
  SAI-002  Paste-sized or larger upload (POST/PUT) to an AI domain
  SAI-003  Large upload (file-sized) to an AI domain
  SAI-004  Repeated uploads by one user in a short window (bulk exfil pattern)
Limits (say this to clients): cannot see personal devices, home networks,
or content inside encrypted sessions. We infer from volume and direction only.
"""
from __future__ import annotations

import pandas as pd

from .common import Finding, GOAL_SHADOW_AI, load_json

PASTE_BYTES = 2_000          # roughly a pasted paragraph or more
FILE_BYTES = 200_000         # roughly a document upload
BULK_COUNT = 5               # uploads in the window
BULK_WINDOW_MIN = 30


def detect(df: pd.DataFrame, sanctioned: set[str] | None = None) -> list[Finding]:
    cfg = load_json("ai_domains.json")
    domains: dict[str, str] = cfg["domains"]
    sanctioned = sanctioned or set(cfg.get("sanctioned_default", []))

    df = df.copy()
    df["ts"] = pd.to_datetime(df["ts"])
    ai = df[df["domain"].isin(domains.keys())].copy()
    ai["tool"] = ai["domain"].map(domains)
    ai = ai[~ai["tool"].isin(sanctioned)]
    findings: list[Finding] = []
    if ai.empty:
        return findings

    # SAI-001: who is using which unapproved AI tool
    for (user, tool), g in ai.groupby(["user", "tool"]):
        findings.append(Finding(
            GOAL_SHADOW_AI, "SAI-001", "low", "high", user,
            f"{user} used {tool} ({len(g)} requests) which is not on the approved list.",
            {"tool": tool, "requests": int(len(g)),
             "first_seen": str(g.ts.min()), "last_seen": str(g.ts.max())}))

    uploads = ai[ai["method"].isin(["POST", "PUT"])]

    # SAI-002 / SAI-003: paste-sized and file-sized uploads
    for (user, tool), g in uploads.groupby(["user", "tool"]):
        big = g[g.bytes_out >= FILE_BYTES]
        paste = g[(g.bytes_out >= PASTE_BYTES) & (g.bytes_out < FILE_BYTES)]
        if len(big):
            findings.append(Finding(
                GOAL_SHADOW_AI, "SAI-003", "high", "medium", user,
                f"{user} sent {len(big)} file-sized upload(s) to {tool}, "
                f"{int(big.bytes_out.sum()/1000)} KB total. Possible document upload.",
                {"tool": tool, "uploads": int(len(big)),
                 "total_bytes": int(big.bytes_out.sum())}))
        if len(paste):
            findings.append(Finding(
                GOAL_SHADOW_AI, "SAI-002", "medium", "medium", user,
                f"{user} sent {len(paste)} paste-sized submission(s) to {tool}. "
                "Content is not visible; this is inferred from size.",
                {"tool": tool, "uploads": int(len(paste)),
                 "total_bytes": int(paste.bytes_out.sum())}))

    # SAI-004: burst of uploads
    for user, g in uploads.groupby("user"):
        g = g.sort_values("ts")
        times = g.ts.tolist()
        for i in range(len(times)):
            window = [t for t in times[i:]
                      if (t - times[i]).total_seconds() <= BULK_WINDOW_MIN * 60]
            if len(window) >= BULK_COUNT:
                findings.append(Finding(
                    GOAL_SHADOW_AI, "SAI-004", "high", "medium", user,
                    f"{user} made {len(window)} uploads to AI tools within "
                    f"{BULK_WINDOW_MIN} minutes.",
                    {"start": str(times[i]), "count": len(window)}))
                break
    return findings
