"""Goal 3 (cloud side): which AI apps and agents have users connected to our M365 / Google accounts?

An OAuth grant is how most AI assistants, note-takers and agents get standing access to
mail, files and calendars. It needs no software on any endpoint, so it is the fastest
place to find unapproved AI. Input: rows from loaders (m365.load_grants / google.load_grants):
  ts, user, app_name, app_id, scopes, admin_consent, platform, src_ip
Rules:
  OAU-001  AI-looking app authorized by a user and not on the approved list
  OAU-002  Unapproved app granted broad data scopes (mail, files, calendar, chat, directory)
  OAU-003  Tenant-wide (admin) consent to an unapproved app
  OAU-004  Same unapproved app granted by several users in a short window (spreading)
Limits: name matching can miss AI apps with neutral names and can flag non-AI ones;
findings say "AI-looking" for that reason. We see the grant, not what the app later does.
"""
from __future__ import annotations

import re

import pandas as pd

from .common import Finding, GOAL_ROGUE_AGENT, load_json


def _is_risky(scope: str, cfg: dict) -> bool:
    if scope in cfg["safe_exact"]:
        return False
    return scope in cfg["also_risky"] or any(scope.startswith(p) for p in cfg["prefixes"])


def _truthy(v) -> bool:
    return str(v).strip().lower() in {"true", "1", "yes"}


def detect(grants: pd.DataFrame, approved_apps: set[str] | None = None) -> list[Finding]:
    cfg = load_json("oauth_apps.json")
    ai_re = re.compile("|".join(cfg["ai_app_patterns"]), re.IGNORECASE)
    approved = {a.lower() for a in (approved_apps or set())}
    findings: list[Finding] = []
    if grants is None or grants.empty:
        return findings

    g = grants.copy()
    g["ts"] = pd.to_datetime(g["ts"])
    g = g[~(g.app_name.str.lower().isin(approved) | g.app_id.str.lower().isin(approved))]

    for _, r in g.iterrows():
        scopes = str(r.scopes).split() if isinstance(r.scopes, str) else []
        risky = [s for s in scopes if _is_risky(s, cfg["risky_scopes"][r.platform])]
        persistent = any(s in cfg["persistence_scopes"] for s in scopes)
        ai = bool(ai_re.search(str(r.app_name)))
        ev = {"app": r.app_name, "app_id": r.app_id, "platform": r.platform,
              "risky_scopes": risky, "persistent_access": persistent,
              "at": str(r.ts), "from_ip": r.src_ip}
        if ai:
            findings.append(Finding(
                GOAL_ROGUE_AGENT, "OAU-001", "high" if risky else "medium", "medium", r.user,
                f"{r.user} connected AI-looking app '{r.app_name}' ({r.platform}), "
                "which is not on the approved list.", ev))
        if risky:
            findings.append(Finding(
                GOAL_ROGUE_AGENT, "OAU-002", "high" if ai else "medium",
                "medium" if ai else "low", r.user,
                f"{r.user} granted '{r.app_name}' broad data access: {', '.join(risky[:5])}"
                f"{' (+ standing access)' if persistent else ''}.", ev))
        if r.platform == "m365" and _truthy(r.admin_consent):
            findings.append(Finding(
                GOAL_ROGUE_AGENT, "OAU-003", "critical" if ai else "high", "high", r.user,
                f"Tenant-wide admin consent given to '{r.app_name}' by {r.user}. "
                "It can act for every user.", ev))

    # OAU-004: one unapproved app adopted by several users quickly
    win = pd.Timedelta(days=cfg["spread_window_days"])
    for app, grp in g.groupby("app_name"):
        grp = grp.sort_values("ts")
        for i in range(len(grp)):
            w = grp[(grp.ts >= grp.ts.iloc[i]) & (grp.ts <= grp.ts.iloc[i] + win)]
            if w.user.nunique() >= cfg["spread_min_users"]:
                findings.append(Finding(
                    GOAL_ROGUE_AGENT, "OAU-004", "medium", "medium", str(app),
                    f"'{app}' was connected by {w.user.nunique()} users within "
                    f"{cfg['spread_window_days']} days. Shadow adoption is spreading.",
                    {"users": sorted(w.user.unique().tolist()), "app": app,
                     "first": str(w.ts.min()), "last": str(w.ts.max())}))
                break
    return findings
