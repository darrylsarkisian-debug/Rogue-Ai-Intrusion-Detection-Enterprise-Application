"""Goal 3: are any autonomous agents running on our systems that we did not approve?

Input: endpoint inventory JSON (one object per host), produced by
endpoint/collect_inventory.ps1 or endpoint/collect_inventory.py:
  {"host": "...", "processes": [{"name","cmdline"}], "listening_ports": [int],
   "large_files": [{"path","mb"}], "gpu_percent": float}
Plus optional egress rows (ts, src_ip, host, domain, key_pattern_hit) for
servers calling AI APIs from unexpected places.
Rules:
  AGT-001  Process matches a local model runtime / MCP server / agent framework
  AGT-002  Listening port matches a local model runtime
  AGT-003  Model weight file on disk above the size threshold
  AGT-004  Sustained GPU load
  AGT-005  Server making repeated AI API calls with an API-key pattern
"""
from __future__ import annotations

from .common import Finding, GOAL_ROGUE_AGENT, load_json

API_CALL_MIN = 20


def detect_inventory(hosts: list[dict], approved: dict[str, set[str]] | None = None
                     ) -> list[Finding]:
    """approved maps host -> set of approved signature kinds/names."""
    sig = load_json("agent_signatures.json")
    approved = approved or {}
    findings: list[Finding] = []

    for h in hosts:
        host = h["host"]
        ok = approved.get(host, set())

        for p in h.get("processes", []):
            name = (p.get("name") or "").lower()
            cmd = (p.get("cmdline") or "").lower()
            for s in sig["process_signatures"]:
                hit = (("name" in s and s["name"] in name) or
                       ("cmdline_contains" in s and s["cmdline_contains"] in cmd))
                if hit and s["kind"] not in ok and name not in ok:
                    findings.append(Finding(
                        GOAL_ROGUE_AGENT, "AGT-001", s["severity"], "high", host,
                        f"{host}: {s['kind'].replace('_', ' ')} running "
                        f"({p.get('name')}), not on the approved list.",
                        {"process": p.get("name"), "kind": s["kind"],
                         "cmdline": (p.get("cmdline") or "")[:200]}))
                    break

        for port in h.get("listening_ports", []):
            label = sig["local_model_ports"].get(str(port))
            if label and label not in ok:
                findings.append(Finding(
                    GOAL_ROGUE_AGENT, "AGT-002", "medium", "medium", host,
                    f"{host}: port {port} is listening, which matches {label}.",
                    {"port": port, "matches": label}))

        for f in h.get("large_files", []):
            ext = "." + f["path"].rsplit(".", 1)[-1].lower()
            if ext in sig["model_file_extensions"] and f["mb"] >= sig["model_file_min_mb"]:
                findings.append(Finding(
                    GOAL_ROGUE_AGENT, "AGT-003", "medium", "high", host,
                    f"{host}: model file {f['path']} ({f['mb']} MB) found.",
                    {"path": f["path"], "mb": f["mb"]}))

        gpu = h.get("gpu_percent", 0)
        if gpu >= sig["gpu_sustained_percent"]:
            findings.append(Finding(
                GOAL_ROGUE_AGENT, "AGT-004", "low", "low", host,
                f"{host}: sustained GPU load {gpu}%. Could be a local model or "
                "a legitimate workload; confirm.",
                {"gpu_percent": gpu}))
    return findings


def detect_egress(rows) -> list[Finding]:
    """rows: DataFrame with src_ip, host, domain, key_pattern_hit (bool)."""
    findings: list[Finding] = []
    hits = rows[rows["key_pattern_hit"]]
    for (src, dom), g in hits.groupby(["src_ip", "domain"]):
        if len(g) >= API_CALL_MIN:
            findings.append(Finding(
                GOAL_ROGUE_AGENT, "AGT-005", "high", "medium", src,
                f"{src} made {len(g)} authenticated calls to {dom}. "
                "Repeated machine calls to an AI API from a server.",
                {"domain": dom, "calls": int(len(g))}))
    return findings
