"""End-to-end demo: logs -> detectors -> cases -> redaction -> triage -> report.

Usage:
  python sim/generate_data.py
  python run_demo.py            # rules-only unless ANTHROPIC_API_KEY is set
  python run_demo.py --no-cloud # force rules-only
"""
import argparse
import json
from pathlib import Path

import pandas as pd

from agent.triage import build_cases, triage
from detectors import automation_speed, oauth_apps, rogue_agents, shadow_ai
from detectors.common import GOAL_AI_SPEED_ATTACK, GOAL_ROGUE_AGENT, GOAL_SHADOW_AI

DATA = Path("data")
TITLES = {GOAL_SHADOW_AI: "GOAL 1  Staff pasting company data into AI tools",
          GOAL_AI_SPEED_ATTACK: "GOAL 2  AI-speed / automation-like attack activity",
          GOAL_ROGUE_AGENT: "GOAL 3  Unapproved autonomous agents on our systems"}


def run(no_cloud: bool = False) -> list[dict]:
    proxy = pd.read_csv(DATA / "proxy_log.csv")
    auth = pd.read_csv(DATA / "auth_log.csv")
    flows = pd.read_csv(DATA / "flow_log.csv")
    egress = pd.read_csv(DATA / "egress_log.csv")
    hosts = json.loads((DATA / "endpoint_inventory.json").read_text())

    # Approved-software list for this client (edit per client in production).
    approved = {"FIN-PC-01": set(), "SRV-APP-02": set()}

    findings = []
    findings += shadow_ai.detect(proxy, sanctioned={"Copilot"})
    findings += automation_speed.detect_auth(auth)
    findings += automation_speed.detect_scan(flows)
    findings += rogue_agents.detect_inventory(hosts, approved)
    findings += rogue_agents.detect_egress(egress)

    # Cloud audit data (M365 / Google), if loaders have produced it. See docs/CLOUD_LOADERS.md
    cloud_users = []
    if (DATA / "oauth_grants.csv").exists():
        grants = pd.read_csv(DATA / "oauth_grants.csv", keep_default_na=False)
        findings += oauth_apps.detect(grants, approved_apps={"Adobe Acrobat", "Zoom"})
        cloud_users += grants.user.unique().tolist()
    if (DATA / "cloud_auth_log.csv").exists():
        cauth = pd.read_csv(DATA / "cloud_auth_log.csv")
        findings += automation_speed.detect_auth(cauth)
        cloud_users += cauth.user.unique().tolist()

    cases = build_cases(findings)
    known = {u: "user" for u in proxy.user.unique()}
    known.update({h["host"]: "host" for h in hosts})
    known.update({u: "user" for u in cloud_users})
    results = triage(cases, client_salt="demo-client-001", known_ids=known,
                     cloud_enabled=not no_cloud)
    return results


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-cloud", action="store_true")
    args = ap.parse_args()
    results = run(args.no_cloud)
    Path("data/report.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    for goal, title in TITLES.items():
        print(f"\n=== {title} ===")
        rs = [r for r in results if r["goal"] == goal]
        if not rs:
            print("  (nothing found)")
        for r in rs:
            print(f"  [{r['severity'].upper():8}] {r['subject']}: {r['explanation']}")
    print(f"\n{len(results)} cases written to data/report.json")


if __name__ == "__main__":
    main()
