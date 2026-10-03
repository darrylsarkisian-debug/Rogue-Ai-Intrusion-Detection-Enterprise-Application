"""Regression tests from a real Entra directoryAudits export (lab tenant, 2026-10-02).

Real-world quirks these cover:
  * 7-digit fractional seconds in activityDateTime
  * ConsentAction.Permissions uses 'Scope:  a b c, CreatedDateTime' (colon, not '=')
  * One consent = several rows sharing a correlationId: 'Consent to application' names the
    client app but lists only new scopes; 'Add delegated permission grant' carries the
    cumulative scope but names Microsoft Graph.
"""
import json

from loaders import m365
from loaders.common import to_ts


def _row(op, corr, target, scope, when="2026-10-02T23:21:12.8648504Z", prop="ConsentAction.Permissions"):
    return {
        "activityDisplayName": op, "activityDateTime": when, "correlationId": corr,
        "initiatedBy": {"user": {"userPrincipalName": "alice.lab@lab.onmicrosoft.com",
                                 "ipAddress": "20.121.114.153"}},
        "targetResources": [{"id": "sp-" + target, "displayName": target, "type": "ServicePrincipal",
                             "modifiedProperties": [
                                 {"displayName": "ConsentContext.IsAdminConsent", "newValue": '"False"'},
                                 {"displayName": prop,
                                  "newValue": f'"[[Id: x, ClientId: 4963498b-e53b-411f-91c7-109da4282e66, '
                                              f'Scope:  {scope}, CreatedDateTime: ]]; "'}]}],
    }


def test_seven_digit_fraction_timestamp():
    assert to_ts("2026-10-02T23:25:10.1488417Z") == "2026-10-02 23:25:10"
    assert to_ts("2026-10-02T23:15:47.107749Z") == "2026-10-02 23:15:47"


def test_consent_and_grant_rows_merge(tmp_path):
    rows = [
        _row("Consent to application", "c1", "Meeting Notes AI Assistant (lab)", "openid profile User.Read Mail.Read"),
        _row("Add delegated permission grant", "c1", "Microsoft Graph",
             "openid profile User.Read Mail.Read offline_access Files.Read.All",
             prop="DelegatedPermissionGrant.Scope"),
        _row("Remove delegated permission grant", "c1", "Microsoft Graph", "openid"),
    ]
    p = tmp_path / "audit.json"
    p.write_text(json.dumps(rows))
    df = m365.load_grants(p)
    assert len(df) == 1
    r = df.iloc[0]
    assert r.app_name == "Meeting Notes AI Assistant (lab)"
    assert r.ts == "2026-10-02 23:21:12"
    assert set(r.scopes.split()) >= {"Mail.Read", "Files.Read.All", "offline_access"}


def test_interrupted_flows_are_not_login_failures(tmp_path):
    def si(code, sec):
        return {"userPrincipalName": "bob@lab.onmicrosoft.com", "ipAddress": "2600:1700::1",
                "createdDateTime": f"2026-10-02T23:00:{sec:02d}Z", "status": {"errorCode": code}}
    p = tmp_path / "si.json"
    p.write_text(json.dumps([si(90094, 1), si(65001, 2), si(50076, 3), si(50140, 4),
                             si(50126, 5), si(0, 6)]))
    df = m365.load_signins(p)
    assert df.result.tolist() == ["fail", "success"]      # only 50126 and 0 survive


def test_repeat_consent_collapses_to_one_finding():
    import pandas as pd
    from detectors import oauth_apps
    base = dict(user="alice@lab", app_name="Meeting Notes AI Assistant (lab)", app_id="x",
                admin_consent=False, platform="m365", src_ip="1.2.3.4")
    g = pd.DataFrame([
        {**base, "ts": "2026-10-02 23:14:22", "scopes": "openid profile User.Read Mail.Read"},
        {**base, "ts": "2026-10-02 23:21:12", "scopes": "openid profile User.Read Mail.Read Files.Read.All"},
    ])
    f = oauth_apps.detect(g)
    assert sorted(x.rule for x in f) == ["OAU-001", "OAU-002"]
    assert "Files.Read.All" in [x for x in f if x.rule == "OAU-002"][0].summary
