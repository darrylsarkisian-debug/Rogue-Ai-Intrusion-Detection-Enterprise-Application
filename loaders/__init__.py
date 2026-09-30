"""Loaders turn raw exports/API output into the tables the detectors expect.

Output schemas (same as the simulated data, so detectors need no changes):
  auth rows:   ts, src_ip, user, result (success|fail)      -> automation_speed.detect_auth
  grant rows:  ts, user, app_name, app_id, scopes, admin_consent, platform, src_ip
                                                              -> oauth_apps.detect
"""
AUTH_COLUMNS = ["ts", "src_ip", "user", "result"]
GRANT_COLUMNS = ["ts", "user", "app_name", "app_id", "scopes", "admin_consent",
                 "platform", "src_ip"]
