"""Google Workspace loaders (Admin SDK Reports API `activities.list` JSON).

  * applicationName=token  -> OAuth authorize events (which apps users connected, which scopes)
  * applicationName=login  -> login_success / login_failure with source IP

Needs only the read-only scope admin.reports.audit.readonly. Save the API response
(or its `items` list) to a .json file, or one activity per line (.jsonl).
"""
from __future__ import annotations

import pandas as pd

from . import AUTH_COLUMNS, GRANT_COLUMNS
from .common import clean_ip, read_records, to_ts


def _params(event: dict) -> dict:
    out = {}
    for p in event.get("parameters") or []:
        out[p.get("name")] = p.get("multiValue") if "multiValue" in p else p.get("value")
    return out


def load_grants(path) -> pd.DataFrame:
    rows = []
    for act in read_records(path):
        if (act.get("id") or {}).get("applicationName", "token") != "token":
            continue
        for ev in act.get("events") or []:
            if ev.get("name") != "authorize":
                continue
            p = _params(ev)
            scopes = p.get("scope") or []
            if isinstance(scopes, str):
                scopes = scopes.split()
            rows.append({"ts": to_ts((act.get("id") or {}).get("time")),
                         "user": (act.get("actor") or {}).get("email", ""),
                         "app_name": p.get("app_name") or p.get("client_id") or "unknown",
                         "app_id": p.get("client_id", ""), "scopes": " ".join(scopes),
                         "admin_consent": False, "platform": "google",
                         "src_ip": clean_ip(act.get("ipAddress"))})
    return pd.DataFrame([r for r in rows if r["user"]], columns=GRANT_COLUMNS)


def load_logins(path) -> pd.DataFrame:
    rows = []
    for act in read_records(path):
        if (act.get("id") or {}).get("applicationName", "login") != "login":
            continue
        for ev in act.get("events") or []:
            name = ev.get("name")
            if name not in {"login_success", "login_failure"}:
                continue
            rows.append((to_ts((act.get("id") or {}).get("time")), clean_ip(act.get("ipAddress")),
                         (act.get("actor") or {}).get("email", ""),
                         "success" if name == "login_success" else "fail"))
    df = pd.DataFrame(rows, columns=AUTH_COLUMNS)
    return df[(df.ts != "") & (df.user != "") & (df.src_ip != "")].reset_index(drop=True)
