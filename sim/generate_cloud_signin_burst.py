"""Goal 2 evidence: a synthetic cloud sign-in burst, in the same shape the M365 loader
produces (ts, src_ip, user, result), for feeding straight into detect_auth().

This is SIMULATED data, not a real attack run against Microsoft's sign-in endpoint.
We do not script actual rapid-fire authentication attempts against any live service,
including our own lab tenant -- that would just be a hand-rolled credential-stuffing
tool pointed at Microsoft's infrastructure, and the pattern a real one produces is
well understood without needing to run one. This generates a log file that LOOKS like
what Entra would emit if that happened, so the detector can be validated the same way
sim/generate_data.py already validates the endpoint and proxy detectors: against a
labeled, deterministic sample, not a live target.

Three scenarios map onto the three automation-speed rules:
  AUT-001  machine-speed burst: one source IP, ~0.3s apart, far faster than a human
  AUT-002  password spray: one source IP, many lab accounts, 1-2 tries each
  AUT-004  fail-then-success: a burst of failures against one account, then one
           success from the same source -- the account to flag as likely compromised

Usage:
  python -m sim.generate_cloud_signin_burst
  python -m loaders.cli --m365-signins data/simulated/cloud_signin_burst.json --out data/simulated
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "simulated"
SEED = 7
TENANT = "rogueailab.onmicrosoft.com"
LAB_USERS = ["alice.lab", "bob.lab", "carol.lab", "dave.lab", "erin.lab",
             "frank.lab", "gina.lab", "hank.lab", "ivy.lab", "jack.lab"]
BURST_IP = "203.0.113.77"             # TEST-NET-3 (RFC 5737): reserved for documentation/examples, not a real host
SPRAY_IP = "203.0.113.141"            # TEST-NET-3: separate source so the spray ratio is not diluted by the burst
COMPROMISE_IP = "198.51.100.23"       # TEST-NET-2: separate source for the fail-then-success scenario


def _row(when: datetime, ip: str, user: str, code: int) -> dict:
    """Graph signIns-shaped record, same fields loaders.m365.load_signins reads."""
    return {
        "createdDateTime": when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "00Z",  # pad to 7 digits like Entra
        "userPrincipalName": f"{user}@{TENANT}",
        "ipAddress": ip,
        "appDisplayName": "Office365 Shell WCSS-Client",
        "status": {"errorCode": code},
    }


def build(start: datetime) -> list[dict]:
    rnd = random.Random(SEED)
    rows: list[dict] = []

    # --- AUT-001: machine-speed burst against one account, all failures ---
    t = start
    for i in range(30):
        t += timedelta(seconds=0.3 + rnd.random() * 0.05)
        rows.append(_row(t, BURST_IP, "bob.lab", 50126))  # bad password

    # --- AUT-002: password spray, same IP, all 10 lab accounts, 2 tries each ---
    t = start + timedelta(minutes=2)
    spray_users = LAB_USERS * 2  # 20 attempts across 10 users = 2 each
    for i, u in enumerate(spray_users):
        t += timedelta(seconds=0.4 + rnd.random() * 0.1)
        rows.append(_row(t, SPRAY_IP, u, 50126))

    # --- AUT-004: burst of failures then one success -> treat account as compromised ---
    t = start + timedelta(minutes=4)
    for i in range(22):
        t += timedelta(seconds=0.3 + rnd.random() * 0.05)
        rows.append(_row(t, COMPROMISE_IP, "carol.lab", 50126))
    t += timedelta(seconds=0.3)
    rows.append(_row(t, COMPROMISE_IP, "carol.lab", 0))  # the one that got through

    return rows


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = build(datetime(2026, 10, 2, 23, 40, 0))
    p = OUT / "cloud_signin_burst.json"
    p.write_text(json.dumps(rows, indent=1))
    print(f"Wrote {len(rows)} simulated sign-in rows -> {p}")


if __name__ == "__main__":
    main()
