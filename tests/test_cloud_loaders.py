"""Loaders must parse the sample exports, and the detectors must fire on the planted scenarios only."""
import subprocess
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detectors import automation_speed, oauth_apps  # noqa: E402
from loaders import google, m365  # noqa: E402

S = ROOT / "data" / "samples"
APPROVED = {"Adobe Acrobat", "Zoom"}


def setup_module(_):
    subprocess.run([sys.executable, str(ROOT / "sim" / "generate_cloud_audit.py")], check=True)


def _grants():
    return pd.concat([m365.load_grants(S / "m365_consents_ual.json"),
                      google.load_grants(S / "google_token_activities.json")], ignore_index=True)


def test_loaders_parse_both_platforms():
    g = _grants()
    assert len(g) == 8 and set(g.platform) == {"m365", "google"}
    chat = g[g.app_name == "ChatGPT Mail Connector"].iloc[0]
    assert bool(chat.admin_consent) and "Mail.ReadWrite" in chat.scopes
    assert chat.app_id == "33333333-cccc-4ccc-8ccc-333333333333"
    assert len(m365.load_signins(S / "m365_signins_graph.json")) == 325
    assert google.load_logins(S / "google_login_activities.json").result.isin(["success", "fail"]).all()


def test_oauth_rules_fire_on_planted_scenarios():
    f = oauth_apps.detect(_grants(), APPROVED)
    by = {(x.rule, x.subject) for x in f}
    assert ("OAU-001", "frank@contoso.example") in by
    assert ("OAU-002", "erin@contoso.example") in by          # Google: Gmail + Drive
    assert ("OAU-003", "admin@contoso.example") in by
    assert ("OAU-004", "Fireflies.ai Notetaker") in by


def test_approved_apps_are_quiet():
    f = oauth_apps.detect(_grants(), APPROVED)
    assert not any(x.evidence.get("app") in APPROVED for x in f if x.rule != "OAU-004")
    assert not any(x.subject in {"alice@contoso.example", "bob@contoso.example",
                                 "dave@contoso.example"} for x in f)


def test_spray_found_in_cloud_signins():
    auth = pd.concat([m365.load_signins(S / "m365_signins_graph.json"),
                      google.load_logins(S / "google_login_activities.json")], ignore_index=True)
    f = automation_speed.detect_auth(auth)
    assert {"AUT-001", "AUT-002", "AUT-004"} <= {x.rule for x in f}
    assert all(x.subject == "203.0.113.50" for x in f)


def test_ual_csv_and_portal_csv_shapes(tmp_path):
    import csv, json
    rec = json.loads((S / "m365_consents_ual.json").read_text())[2]
    p = tmp_path / "ual.csv"
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["CreationDate", "UserIds", "Operations", "AuditData"])
        w.writerow([rec["CreationTime"], rec["UserId"], rec["Operation"], json.dumps(rec)])
    g = m365.load_grants(p)
    assert len(g) == 1 and g.iloc[0].app_name == "Fireflies.ai Notetaker"
    q = tmp_path / "signins.csv"
    q.write_text("Date (UTC),User,IP address,Status\n9/24/2026 1:05:00 PM,a@x.com,1.2.3.4,Success\n"
                 "9/24/2026 1:06:00 PM,a@x.com,1.2.3.4,Failure\n", encoding="utf-8")
    s = m365.load_signins(q)
    assert list(s.result) == ["success", "fail"] and s.iloc[0].ts == "2026-09-24 13:05:00"
