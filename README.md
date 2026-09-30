# Rogue AI Detection (MSP edition)

A sensor plus triage agent that answers three questions for a client:

1. Are staff pasting company data into AI tools? (`detectors/shadow_ai.py`)
2. Is someone attacking us with AI-speed automation? (`detectors/automation_speed.py`)
3. Are any autonomous agents running on our systems that we did not approve? (`detectors/rogue_agents.py`)

Rules and baselines do the detecting. The AI agent (`agent/triage.py`) only explains
cases, on redacted summaries, read-only. Cloud step can be switched off per client.

## Quick start (lab demo)

```
pip install -r requirements.txt
python sim/generate_data.py      # fake client network with one scenario per goal
python run_demo.py --no-cloud    # rules-only
set ANTHROPIC_API_KEY=...        # optional: enables cloud triage (PowerShell: $env:ANTHROPIC_API_KEY="...")
python run_demo.py
pytest                           # all three goals must fire; benign users must not
```

## Layout

| Path | Purpose |
|---|---|
| `config/ai_domains.json` | Versioned AI service domain list (a product asset) |
| `config/agent_signatures.json` | Process, port, and model-file signatures for local agents |
| `detectors/` | One module per goal |
| `agent/` | Redaction, case grouping, triage prompt and API call, audit log |
| `endpoint/collect_inventory.ps1` | Read-only Windows collector for Goal 3 |
| `sim/generate_data.py` | Repeatable simulated client data |
| `docs/` | Plan, coverage limits, pitch material |

## Cloud audit loaders (M365 / Google)

`loaders/` turns Microsoft 365 and Google Workspace audit exports into detector-ready tables;
`detectors/oauth_apps.py` flags unapproved AI apps and agents that users connected. See `docs/CLOUD_LOADERS.md`.

## Honest limits (put these in every proposal)

No coverage for personal phones, home networks, off-network laptops, or encrypted
content. Goal 2 reports "automation-like activity" with a confidence level; it does
not prove an attacker is an AI. Goal 1 infers pasted data from upload size and
direction, not content.

## Next: replace simulated data with real sources

Zeek/Suricata (network), Wazuh (endpoint + logs), M365/Google audit logs (OAuth grants).
Write a thin loader per source that outputs the same CSV/JSON columns the detectors expect.
