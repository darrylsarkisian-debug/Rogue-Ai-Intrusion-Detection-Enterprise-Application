"""Each of the three goals must fire on the simulated data, and benign users must not."""
import json
import subprocess
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detectors import automation_speed, rogue_agents, shadow_ai  # noqa: E402


def setup_module(_):
    subprocess.run([sys.executable, str(ROOT / "sim" / "generate_data.py")], check=True)


def _load(name):
    return pd.read_csv(ROOT / "data" / name)


def test_goal1_flags_jsmith_not_alice():
    f = shadow_ai.detect(_load("proxy_log.csv"), sanctioned={"Copilot"})
    subjects = {(x.subject, x.rule) for x in f}
    assert ("jsmith", "SAI-002") in subjects
    assert ("jsmith", "SAI-003") in subjects
    assert ("jsmith", "SAI-004") in subjects
    # carol only browsed: visibility finding but no upload finding
    assert ("carol", "SAI-001") in subjects
    assert not any(x.subject == "carol" and x.rule in {"SAI-002", "SAI-003"} for x in f)
    assert not any(x.subject == "alice" for x in f)


def test_goal2_flags_attacker_ip_only():
    a = automation_speed.detect_auth(_load("auth_log.csv"))
    s = automation_speed.detect_scan(_load("flow_log.csv"))
    rules = {x.rule for x in a + s}
    assert {"AUT-001", "AUT-002", "AUT-003", "AUT-004"} <= rules
    assert all(x.subject == "198.51.100.23" for x in a + s)


def test_goal3_flags_dev_laptop_and_server():
    hosts = json.loads((ROOT / "data" / "endpoint_inventory.json").read_text())
    f = rogue_agents.detect_inventory(hosts)
    flagged = {x.subject for x in f}
    assert "DEV-LAPTOP-07" in flagged
    assert "FIN-PC-01" not in flagged and "HR-PC-02" not in flagged
    rules = {x.rule for x in f if x.subject == "DEV-LAPTOP-07"}
    assert {"AGT-001", "AGT-002", "AGT-003", "AGT-004"} <= rules
    e = rogue_agents.detect_egress(_load("egress_log.csv"))
    assert any(x.rule == "AGT-005" for x in e)


def test_approved_list_suppresses_finding():
    hosts = json.loads((ROOT / "data" / "endpoint_inventory.json").read_text())
    f = rogue_agents.detect_inventory(hosts, {"DEV-LAPTOP-07": {"local_model_runtime", "Ollama"}})
    assert not any(x.rule in {"AGT-002"} and x.evidence.get("matches") == "Ollama" for x in f)


def test_redaction_removes_identifiers():
    from agent.redact import Pseudonymizer
    p = Pseudonymizer("salt")
    out = p.redact_case({"s": "jsmith on 10.0.1.19 at DEV-LAPTOP-07"},
                        {"jsmith": "user", "DEV-LAPTOP-07": "host"})
    assert "jsmith" not in out["s"] and "10.0.1.19" not in out["s"]
    assert "DEV-LAPTOP-07" not in out["s"]


def test_simulated_cloud_signin_burst_triggers_aut_rules():
    """sim/generate_cloud_signin_burst.py is a labeled, synthetic sign-in log (not a live
    attack run) built to exercise AUT-001 and AUT-004 end to end on Goal 2."""
    import pandas as pd
    from sim.generate_cloud_signin_burst import build
    from datetime import datetime
    from detectors import automation_speed

    rows = build(datetime(2026, 1, 1, 0, 0, 0))
    auth = pd.DataFrame(
        [{"ts": r["createdDateTime"], "src_ip": r["ipAddress"],
          "user": r["userPrincipalName"], "result": "success" if r["status"]["errorCode"] == 0 else "fail"}
         for r in rows])
    findings = automation_speed.detect_auth(auth)
    rules = {f.rule for f in findings}
    assert "AUT-001" in rules      # machine-speed burst
    assert "AUT-004" in rules      # fail-then-success on carol.lab
    assert "AUT-002" in rules    # 10 lab accounts, sprayed from a separate source IP
