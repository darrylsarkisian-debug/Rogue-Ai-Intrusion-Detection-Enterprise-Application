"""Group findings into cases, redact, and ask the cloud agent to triage.

Works offline: with no ANTHROPIC_API_KEY (or cloud disabled per client) a
rules-only summary is produced, so the product never depends on the cloud.
Every prompt and response is appended to audit.jsonl.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from detectors.common import Finding
from .redact import Pseudonymizer

SYSTEM_PROMPT = (Path(__file__).parent / "system_prompt.md").read_text(encoding="utf-8")
MODEL = os.environ.get("TRIAGE_MODEL", "claude-sonnet-5-5")
SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def build_cases(findings: list[Finding]) -> list[dict]:
    """One case per (goal, subject). LLM calls scale with cases, not events."""
    grouped: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        grouped[(f.goal, f.subject)].append(f)
    cases = []
    for i, ((goal, subject), fs) in enumerate(sorted(grouped.items()), 1):
        top = max(fs, key=lambda f: SEV_ORDER[f.severity])
        cases.append({
            "case_id": f"CASE-{i:03d}", "goal": goal, "subject": subject,
            "top_severity": top.severity,
            "findings": [f.to_dict() for f in fs],
        })
    return sorted(cases, key=lambda c: -SEV_ORDER[c["top_severity"]])


def rules_only_summary(case: dict) -> dict:
    top = max(case["findings"], key=lambda f: SEV_ORDER[f["severity"]])
    return {
        "severity": case["top_severity"], "goal": case["goal"],
        "explanation": top["summary"],
        "likely_cause": "Rules-only mode: no AI reasoning applied.",
        "confidence": top["confidence"],
        "recommended_action": "Technician review of the listed findings.",
        "coverage_note": "Detection is limited to managed networks and devices.",
        "mode": "rules_only",
    }


def triage(cases: list[dict], client_salt: str, known_ids: dict[str, str],
           cloud_enabled: bool = True, audit_path: str = "audit.jsonl") -> list[dict]:
    use_cloud = cloud_enabled and bool(os.environ.get("ANTHROPIC_API_KEY"))
    client = None
    if use_cloud:
        import anthropic  # imported lazily so the sensor runs without it
        client = anthropic.Anthropic()
    pseudo = Pseudonymizer(client_salt)
    results = []
    for case in cases:
        if not use_cloud:
            results.append({"case_id": case["case_id"], "subject": case["subject"],
                            **rules_only_summary(case)})
            continue
        redacted = pseudo.redact_case(case, known_ids)
        payload = json.dumps(redacted)
        resp = client.messages.create(
            model=MODEL, max_tokens=600, system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"<case>{payload}</case>"}])
        text = resp.content[0].text
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = {**rules_only_summary(case), "note": "agent output not valid JSON"}
        with open(audit_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                                 "case": case["case_id"], "prompt": payload,
                                 "response": text}) + "\n")
        results.append({"case_id": case["case_id"], "subject": case["subject"],
                        **parsed, "mode": "cloud"})
    return results
