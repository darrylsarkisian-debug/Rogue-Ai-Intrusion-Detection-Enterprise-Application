"""Shared types for all three detection tracks."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

# The three goals of the product. Every finding maps to exactly one.
GOAL_SHADOW_AI = "goal1_data_to_ai"
GOAL_AI_SPEED_ATTACK = "goal2_ai_speed_attack"
GOAL_ROGUE_AGENT = "goal3_unapproved_agent"


@dataclass
class Finding:
    goal: str
    rule: str
    severity: str          # low | medium | high | critical
    confidence: str        # low | medium | high  (never claim certainty)
    subject: str           # user, host or source IP
    summary: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def load_json(name: str) -> dict:
    return json.loads((CONFIG_DIR / name).read_text(encoding="utf-8"))
