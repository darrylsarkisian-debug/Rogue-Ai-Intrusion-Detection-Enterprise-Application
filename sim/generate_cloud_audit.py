"""Write fake M365 and Google audit exports in the same shapes the real APIs return.

Scenarios (all invented; 203.0.113.0/24 is a documentation-only IP range):
  * benign: users connect approved apps; normal sign-ins
  * Goal 3: frank connects an AI note-taker with mail+file scopes; three users connect the
    same AI app in a week; an admin gives tenant-wide consent to an AI connector;
    a Google user connects an AI coding tool with Gmail+Drive scopes
  * Goal 2: a password spray then success from 203.0.113.50 against M365
Deterministic (seeded). Output: data/samples/*.json
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "samples"
START = datetime(2026, 9, 22, 9, 0, 0)
DOM = "contoso.example"
USERS = [f"{n}@{DOM}" for n in
         ["alice", "bob", "carol", "dave", "erin", "frank", "gina", "hank", "ivy", "jsmith"]]
APPROVED_APP = ("Adobe Acrobat", "11111111-aaaa-4aaa-8aaa-111111111111")
NOTETAKER = ("Fireflies.ai Notetaker", "22222222-bbbb-4bbb-8bbb-222222222222")
CONNECTOR = ("ChatGPT Mail Connector", "33333333-cccc-4ccc-8ccc-333333333333")


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def m365_consent(dt, user, app, scopes, admin=False, ip="198.51.100.10"):
    name, cid = app
    perms = f"[[ClientId = {cid}, ConsentType = {'AllPrincipals' if admin else 'Principal'}, " \
            f"Scope = {scopes}, StartTime = {iso(dt)}]]"
    return {"CreationTime": iso(dt), "Operation": "Consent to application.",
            "UserId": user, "ClientIP": ip, "Workload": "AzureActiveDirectory",
            "Target": [{"ID": f"ServicePrincipal_{cid}", "Type": 2}, {"ID": name, "Type": 1}],
            "ModifiedProperties": [
                {"Name": "ConsentContext.IsAdminConsent", "NewValue": str(admin), "OldValue": ""},
                {"Name": "ConsentAction.Permissions", "NewValue": perms, "OldValue": ""},
                {"Name": "TargetId.ServicePrincipalNames", "NewValue": name, "OldValue": ""}]}


def signin(dt, user, ip, ok):
    return {"createdDateTime": iso(dt), "userPrincipalName": user, "ipAddress": ip,
            "appDisplayName": "Office 365 Exchange Online",
            "status": {"errorCode": 0 if ok else 50126}}


def google_act(dt, email, app, name, params, ip="198.51.100.20"):
    return {"id": {"time": iso(dt), "applicationName": app}, "actor": {"email": email},
            "ipAddress": ip, "events": [{"type": app, "name": name, "parameters": params}]}


def main() -> None:
    rnd = random.Random(7)
    OUT.mkdir(parents=True, exist_ok=True)

    # ---- M365 consent events (UAL AuditData records) ----
    grants = [m365_consent(START + timedelta(hours=2), USERS[0], APPROVED_APP,
                           "Files.Read User.Read", ip="198.51.100.11"),
              m365_consent(START + timedelta(days=1, hours=1), USERS[1], APPROVED_APP,
                           "Files.Read User.Read", ip="198.51.100.12")]
    # frank: AI note-taker, mail + files + standing access
    grants.append(m365_consent(START + timedelta(days=1, hours=3), USERS[5], NOTETAKER,
                               "Mail.Read Files.Read.All Calendars.Read offline_access User.Read",
                               ip="198.51.100.15"))
    for i, u in enumerate([USERS[2], USERS[7]]):   # two more users within the week
        grants.append(m365_consent(START + timedelta(days=2 + i, hours=4), u, NOTETAKER,
                                   "Calendars.Read User.Read", ip=f"198.51.100.{20+i}"))
    # admin gives tenant-wide consent to an AI connector
    grants.append(m365_consent(START + timedelta(days=4, hours=2), f"admin@{DOM}", CONNECTOR,
                               "Mail.ReadWrite Mail.Send offline_access", admin=True,
                               ip="198.51.100.30"))
    (OUT / "m365_consents_ual.json").write_text(json.dumps(grants, indent=2))

    # ---- M365 sign-ins (Graph signIns) ----
    si = []
    for _ in range(250):
        u = rnd.choice(USERS)
        si.append(signin(START + timedelta(seconds=rnd.randint(0, 6 * 86400)), u,
                         f"198.51.100.{USERS.index(u) + 40}", rnd.random() > 0.04))
    t = START + timedelta(days=3, hours=5, minutes=13)
    for i in range(75):   # spray: ~0.4s apart, 25 accounts, then one success
        u = f"user{i % 25:02d}@{DOM}" if i < 74 else USERS[8]
        si.append(signin(t + timedelta(milliseconds=400 * i), u, "203.0.113.50", i == 74))
    si.sort(key=lambda r: r["createdDateTime"])
    (OUT / "m365_signins_graph.json").write_text(json.dumps({"value": si}, indent=2))

    # ---- Google token (OAuth authorize) ----
    def authz(dt, email, app, cid, scopes):
        return google_act(dt, email, "token", "authorize",
                          [{"name": "app_name", "value": app}, {"name": "client_id", "value": cid},
                           {"name": "scope", "multiValue": scopes}])
    G = "https://www.googleapis.com/auth/"
    gtok = [authz(START + timedelta(days=1), USERS[3], "Zoom", "zoom-client-1.apps.example",
                  [G + "calendar.freebusy", G + "userinfo.email"]),
            authz(START + timedelta(days=2, hours=6), USERS[4], "Cursor", "cursor-client-1.apps.example",
                  [G + "gmail.readonly", G + "drive", G + "userinfo.email"])]
    (OUT / "google_token_activities.json").write_text(json.dumps({"items": gtok}, indent=2))

    # ---- Google login ----
    gl = []
    for _ in range(120):
        u = rnd.choice(USERS)
        gl.append(google_act(START + timedelta(seconds=rnd.randint(0, 6 * 86400)), u, "login",
                             "login_success" if rnd.random() > 0.04 else "login_failure",
                             [{"name": "login_type", "value": "google_password"}],
                             ip=f"198.51.100.{USERS.index(u) + 40}"))
    gl.sort(key=lambda r: r["id"]["time"])
    (OUT / "google_login_activities.json").write_text(json.dumps({"items": gl}, indent=2))
    print(f"wrote sample exports to {OUT}")


if __name__ == "__main__":
    main()
