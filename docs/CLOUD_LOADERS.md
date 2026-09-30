# Cloud audit loaders (Microsoft 365 / Entra and Google Workspace)

Goal: find unapproved AI apps and machine-speed logins from cloud audit logs, with nothing
installed on any endpoint. Read-only access is enough.

## What each source gives us

| Source | Gives | Feeds |
|---|---|---|
| M365 consent events (Unified Audit Log "Consent to application", or Entra audit log) | Which app a user or admin connected, which scopes, admin-wide or not | `detectors/oauth_apps.py` (OAU-001..004) |
| Entra sign-in logs | Who logged in, from which IP, success or failure | `automation_speed.detect_auth` (AUT-001/002/004) |
| Google Admin Reports, application `token` | Which OAuth apps users authorized, which scopes | `oauth_apps.py` |
| Google Admin Reports, application `login` | login_success / login_failure with IP | `automation_speed.detect_auth` |

## Getting the exports (read-only roles)

- **M365 consents:** Purview portal > Audit > search the activity "Consent to application" > Export
  (CSV, keep the AuditData column). Or Graph `GET /auditLogs/directoryAudits` filtered on the activity.
  Needs Audit Logs reader rights (Global Reader / Security Reader).
- **M365 sign-ins:** Entra admin center > Monitoring > Sign-in logs > Download (CSV or JSON),
  or Graph `GET /auditLogs/signIns`. Needs Reports Reader / Security Reader.
- **Google:** Admin SDK Reports API `activities.list` for `applicationName=token` and `login`
  with the read-only scope `admin.reports.audit.readonly`. Save the response JSON.

## Run

```
python sim/generate_cloud_audit.py        # fake exports in data/samples/ (demo only)
python -m loaders.cli --m365-grants data/samples/m365_consents_ual.json ^
                      --m365-signins data/samples/m365_signins_graph.json ^
                      --google-grants data/samples/google_token_activities.json ^
                      --google-logins data/samples/google_login_activities.json --out data
python run_demo.py --no-cloud             # picks up data/oauth_grants.csv and cloud_auth_log.csv
```

Real client exports go in `data/real/` (gitignored). Never commit them.

## Approved apps

`run_demo.py` passes an approved-app list (`{"Adobe Acrobat", "Zoom"}` in the demo). In production this is a
per-client setting: anything a client has approved is silent, everything else is reported.

## Honest limits (repeat in proposals)

- The loaders follow the documented record shapes, but only sample data has been run through them.
  **First real tenant export may need small parser fixes.** Budget for that.
- AI detection is by app display name (`config/oauth_apps.json`). Apps with neutral names are missed,
  and some non-AI apps match generic words. Findings say "AI-looking". Expand the pattern list from real data.
- We see that a grant happened, not what the app does afterward. Pair with mailbox/file access audit later.
- Sign-in times are kept to the second, so very fast bursts look like "0.00s gaps". That still counts as automation-like.
- Shared egress IPs (offices, VPNs, cloud NAT) can make many users look like one source. Allow-list known IPs per client.
- Purview audit retention and licensing differ by plan; some tenants will not have consent events for long.

## Next (needs real data, later)

- Graph `signIns` for service principals and non-interactive sign-ins (machine identities).
- M365 `CopilotInteraction` and file download volume events for Goal 1.
- Zeek and Wazuh loaders from the lab, writing the same table shapes.
