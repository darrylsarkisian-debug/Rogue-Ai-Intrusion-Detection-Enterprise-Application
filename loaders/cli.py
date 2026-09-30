"""Convert raw cloud audit exports into detector-ready CSVs.

  python -m loaders.cli --m365-grants ual.csv --m365-signins signins.json \
                        --google-grants token.json --google-logins login.json --out data

Any subset of inputs works. Writes <out>/oauth_grants.csv and <out>/cloud_auth_log.csv.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from . import AUTH_COLUMNS, GRANT_COLUMNS, google, m365


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m365-grants", nargs="*", default=[])
    ap.add_argument("--m365-signins", nargs="*", default=[])
    ap.add_argument("--google-grants", nargs="*", default=[])
    ap.add_argument("--google-logins", nargs="*", default=[])
    ap.add_argument("--out", default="data")
    a = ap.parse_args()

    grants = [m365.load_grants(p) for p in a.m365_grants] + \
             [google.load_grants(p) for p in a.google_grants]
    auth = [m365.load_signins(p) for p in a.m365_signins] + \
           [google.load_logins(p) for p in a.google_logins]
    out = Path(a.out)
    out.mkdir(exist_ok=True)
    g = pd.concat(grants, ignore_index=True) if grants else pd.DataFrame(columns=GRANT_COLUMNS)
    u = pd.concat(auth, ignore_index=True) if auth else pd.DataFrame(columns=AUTH_COLUMNS)
    g.sort_values("ts").to_csv(out / "oauth_grants.csv", index=False)
    u.sort_values("ts").to_csv(out / "cloud_auth_log.csv", index=False)
    print(f"{len(g)} app grants -> {out/'oauth_grants.csv'}")
    print(f"{len(u)} sign-in rows -> {out/'cloud_auth_log.csv'}")


if __name__ == "__main__":
    main()
