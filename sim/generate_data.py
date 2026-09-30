"""Generate a fake client network so the demo runs without a real client.

Baseline is normal office activity; three scenarios are injected, one per goal:
  1. 'jsmith' pastes and uploads data to ChatGPT and DeepSeek
  2. 198.51.100.23 sprays/logs in at machine speed and scans the LAN
  3. host DEV-LAPTOP-07 runs Ollama and an MCP server; SRV-APP-02 hammers an AI API
Deterministic (seeded) so the demo is repeatable.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

OUT = Path(__file__).resolve().parent.parent / "data"
SEED = 42
START = datetime(2026, 9, 29, 9, 0, 0)
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "gina", "hank", "ivy", "jsmith"]
NORMAL = ["outlook.office.com", "teams.microsoft.com", "github.com", "salesforce.com",
          "slack.com", "zoom.us", "google.com", "stackoverflow.com"]


def main() -> None:
    rnd = random.Random(SEED)
    OUT.mkdir(exist_ok=True)

    # --- proxy log ---
    rows = []
    for _ in range(3000):
        u = rnd.choice(USERS)
        rows.append((START + timedelta(seconds=rnd.randint(0, 8 * 3600)),
                     f"10.0.1.{USERS.index(u) + 10}", u, rnd.choice(NORMAL),
                     rnd.choice(["GET", "GET", "GET", "POST"]), rnd.randint(300, 1500)))
    # light, benign chatgpt use by carol (visibility only)
    for i in range(6):
        rows.append((START + timedelta(minutes=30 * i), "10.0.1.12", "carol",
                     "chatgpt.com", "GET", 400))
    # Goal 1: jsmith pastes and uploads
    t = START + timedelta(hours=3)
    for i in range(7):
        rows.append((t + timedelta(minutes=3 * i), "10.0.1.19", "jsmith",
                     "chatgpt.com", "POST", rnd.randint(2500, 9000)))
    rows.append((t + timedelta(minutes=25), "10.0.1.19", "jsmith",
                 "chat.deepseek.com", "POST", 480_000))
    proxy = pd.DataFrame(rows, columns=["ts", "src_ip", "user", "domain", "method", "bytes_out"])
    proxy.sort_values("ts").to_csv(OUT / "proxy_log.csv", index=False)

    # --- auth log ---
    arows = []
    for _ in range(300):
        u = rnd.choice(USERS)
        arows.append((START + timedelta(seconds=rnd.randint(0, 8 * 3600)),
                      f"10.0.1.{USERS.index(u) + 10}", u,
                      "success" if rnd.random() > 0.05 else "fail"))
    # Goal 2: spray at machine speed from an external IP, one success
    t = START + timedelta(hours=5, minutes=13)
    for i in range(60):
        arows.append((t + timedelta(seconds=i * 0.4 + rnd.random() * 0.05),
                      "198.51.100.23", f"user{i % 30}", "fail"))
    arows.append((t + timedelta(seconds=25), "198.51.100.23", "svc-backup", "success"))
    auth = pd.DataFrame(arows, columns=["ts", "src_ip", "user", "result"])
    auth.sort_values("ts").to_csv(OUT / "auth_log.csv", index=False)

    # --- flow log (scan) ---
    frows = []
    for _ in range(400):
        frows.append((START + timedelta(seconds=rnd.randint(0, 8 * 3600)),
                      f"10.0.1.{rnd.randint(10, 30)}", "10.0.2.5", rnd.choice([443, 445, 53])))
    t = START + timedelta(hours=5, minutes=20)
    for i in range(120):
        frows.append((t + timedelta(seconds=i * 0.3), "198.51.100.23",
                      f"10.0.2.{rnd.randint(1, 60)}", rnd.choice([22, 80, 135, 445, 3389, 8080])))
    pd.DataFrame(frows, columns=["ts", "src_ip", "dst_ip", "dst_port"]).sort_values("ts").to_csv(
        OUT / "flow_log.csv", index=False)

    # --- endpoint inventory (Goal 3) ---
    hosts = [
        {"host": "FIN-PC-01", "processes": [{"name": "excel.exe", "cmdline": "excel.exe"}],
         "listening_ports": [135, 445], "large_files": [], "gpu_percent": 3},
        {"host": "HR-PC-02", "processes": [{"name": "chrome.exe", "cmdline": "chrome.exe"}],
         "listening_ports": [135], "large_files": [], "gpu_percent": 1},
        {"host": "DEV-LAPTOP-07",
         "processes": [{"name": "ollama.exe", "cmdline": "ollama serve"},
                       {"name": "node.exe",
                        "cmdline": "node npx @modelcontextprotocol/server-filesystem C:\\Users"}],
         "listening_ports": [135, 11434, 3000],
         "large_files": [{"path": "C:\\Users\\dev\\.ollama\\llama3-8b.gguf", "mb": 4900}],
         "gpu_percent": 88},
        {"host": "SRV-APP-02", "processes": [{"name": "python.exe", "cmdline": "python worker.py"}],
         "listening_ports": [443], "large_files": [], "gpu_percent": 2},
    ]
    (OUT / "endpoint_inventory.json").write_text(json.dumps(hosts, indent=2), encoding="utf-8")

    # --- egress (API-key pattern hits from a server) ---
    erows = [(START + timedelta(minutes=i), "10.0.3.22", "SRV-APP-02",
              "api.openai.com", True) for i in range(45)]
    erows += [(START + timedelta(minutes=i), "10.0.1.14", "alice", "github.com", False)
              for i in range(10)]
    pd.DataFrame(erows, columns=["ts", "src_ip", "host", "domain", "key_pattern_hit"]).to_csv(
        OUT / "egress_log.csv", index=False)
    print(f"Wrote sample data to {OUT}")


if __name__ == "__main__":
    main()
