"""Microsoft 365 / Entra loaders.

Accepts exports an MSP can pull with read-only roles (Security Reader / Global Reader):
  * Purview Unified Audit Log export (CSV with an AuditData column, or JSON of AuditData records)
  * Microsoft Graph directoryAudits (auditLogs/directoryAudits) JSON
  * Entra sign-in logs: Graph auditLogs/signIns JSON, or the portal CSV download

Only delegated/consent events and sign-in outcomes are extracted. No mail, file or
message content is read.
"""
from __future__ import annotations

import re

import pandas as pd

from . import AUTH_COLUMNS, GRANT_COLUMNS
from .common import as_obj, ci_get, clean_ip, read_records, to_ts

CONSENT_OPS = {"consent to application", "consent to application.",
               "add delegated permission grant", "add delegated permission grant.",
               "add oauth2permissiongrant", "add oauth2permissiongrant."}
GUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")


def _props(mods) -> dict:
    """ModifiedProperties (UAL: Name/NewValue; Graph: displayName/newValue) -> {name: value}."""
    out = {}
    for m in mods or []:
        name = m.get("Name") or m.get("displayName") or ""
        val = m.get("NewValue") if "NewValue" in m else m.get("newValue")
        out[name] = str(val).strip().strip('"') if val is not None else ""
    return out


def _scopes_from(props: dict) -> tuple[str, str]:
    """Return (scopes, client_id) from the permission-detail property."""
    blob = props.get("ConsentAction.Permissions", "") or props.get("DelegatedPermissionGrant.Scope", "")
    scopes = ""
    m = re.search(r"Scope\s*=\s*([^,\]]+)", blob)
    if m:
        scopes = m.group(1).strip()
    elif blob and "=" not in blob:
        scopes = blob.strip()
    cid = re.search(r"ClientId\s*=\s*(" + GUID.pattern + ")", blob)
    return " ".join(scopes.split()), (cid.group(1) if cid else "")


def _grant_from_ual(rec: dict):
    op = str(rec.get("Operation", "")).strip().lower()
    if op not in CONSENT_OPS:
        return None
    props = _props(rec.get("ModifiedProperties"))
    scopes, cid = _scopes_from(props)
    app = props.get("TargetId.ServicePrincipalNames", "").split(";")[0]
    for t in rec.get("Target") or []:
        tid = str(t.get("ID", ""))
        if not app and t.get("Type") == 1 and not tid.startswith("ServicePrincipal_"):
            app = tid
        if not cid and tid.startswith("ServicePrincipal_"):
            cid = tid.split("_", 1)[1]
    admin = props.get("ConsentContext.IsAdminConsent", "").lower() == "true" \
        or props.get("ConsentContext.OnBehalfOfAll", "").lower() == "true"
    return {"ts": to_ts(rec.get("CreationTime")), "user": rec.get("UserId", ""),
            "app_name": app or cid or "unknown", "app_id": cid, "scopes": scopes,
            "admin_consent": admin, "platform": "m365",
            "src_ip": clean_ip(rec.get("ClientIP"))}


def _grant_from_graph(rec: dict):
    op = str(rec.get("activityDisplayName", "")).strip().lower()
    if op not in CONSENT_OPS:
        return None
    by = (rec.get("initiatedBy") or {}).get("user") or {}
    app, cid, props = "", "", {}
    for t in rec.get("targetResources") or []:
        p = _props(t.get("modifiedProperties"))
        props.update(p)
        if str(t.get("type", "")).lower() == "serviceprincipal":
            app = app or t.get("displayName") or ""
            cid = cid or t.get("id") or ""
    scopes, cid2 = _scopes_from(props)
    admin = props.get("ConsentContext.IsAdminConsent", "").lower() == "true" \
        or props.get("ConsentContext.OnBehalfOfAll", "").lower() == "true"
    return {"ts": to_ts(rec.get("activityDateTime")), "user": by.get("userPrincipalName", ""),
            "app_name": app or cid or "unknown", "app_id": cid or cid2, "scopes": scopes,
            "admin_consent": admin, "platform": "m365", "src_ip": clean_ip(by.get("ipAddress"))}


def load_grants(path) -> pd.DataFrame:
    """OAuth / consent grants from a UAL export or Graph directoryAudits."""
    rows = []
    for rec in read_records(path):
        blob = as_obj(ci_get(rec, "AuditData")) if ci_get(rec, "AuditData") else None
        r = None
        if isinstance(blob, dict):
            r = _grant_from_ual(blob)
        elif "Operation" in rec:
            r = _grant_from_ual(rec)
        elif "activityDisplayName" in rec:
            r = _grant_from_graph(rec)
        if r and r["user"]:
            rows.append(r)
    return pd.DataFrame(rows, columns=GRANT_COLUMNS)


def load_signins(path) -> pd.DataFrame:
    """Sign-in outcomes -> auth rows (ts, src_ip, user, result)."""
    rows = []
    for rec in read_records(path):
        if "userPrincipalName" in rec:                      # Graph signIns
            code = (rec.get("status") or {}).get("errorCode", 0)
            rows.append((to_ts(rec.get("createdDateTime")), clean_ip(rec.get("ipAddress")),
                         rec["userPrincipalName"], "success" if int(code or 0) == 0 else "fail"))
        elif ci_get(rec, "AuditData"):                       # UAL export row
            d = as_obj(ci_get(rec, "AuditData")) or {}
            r = _signin_from_ual(d)
            if r:
                rows.append(r)
        elif "Operation" in rec:                             # UAL JSON record
            r = _signin_from_ual(rec)
            if r:
                rows.append(r)
        elif ci_get(rec, "IP address", "IPAddress"):         # portal CSV
            status = str(ci_get(rec, "Status", "Sign-in status")).lower()
            rows.append((to_ts(ci_get(rec, "Date (UTC)", "Date", "CreatedDateTime")),
                         clean_ip(ci_get(rec, "IP address", "IPAddress")),
                         ci_get(rec, "User", "Username", "UserPrincipalName"),
                         "success" if status.startswith("success") else "fail"))
    df = pd.DataFrame(rows, columns=AUTH_COLUMNS)
    return df[(df.ts != "") & (df.user != "") & (df.src_ip != "")].reset_index(drop=True)


def _signin_from_ual(d: dict):
    op = str(d.get("Operation", "")).lower()
    if op not in {"userloggedin", "userloginfailed"}:
        return None
    return (to_ts(d.get("CreationTime")), clean_ip(d.get("ClientIP")),
            d.get("UserId", ""), "success" if op == "userloggedin" else "fail")
