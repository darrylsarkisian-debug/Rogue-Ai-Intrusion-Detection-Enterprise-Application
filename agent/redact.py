"""Redaction runs locally BEFORE anything reaches the cloud agent.

Usernames, hostnames and IPs become stable pseudonyms per client so the agent
can reason about "user_3 did X then Y" without learning who user_3 is.
The mapping never leaves the sensor.
"""
from __future__ import annotations

import hashlib
import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class Pseudonymizer:
    def __init__(self, client_salt: str):
        self.salt = client_salt
        self.map: dict[str, str] = {}

    def alias(self, value: str, prefix: str) -> str:
        key = f"{prefix}:{value}"
        if key not in self.map:
            h = hashlib.sha256((self.salt + key).encode()).hexdigest()[:4]
            self.map[key] = f"{prefix}_{h}"
        return self.map[key]

    def redact_text(self, text: str, known: dict[str, str]) -> str:
        """known maps real identifier -> prefix (user, host)."""
        # longest identifiers first, so 'alice@corp.com' is not half-eaten by 'alice'
        for real, prefix in sorted(known.items(), key=lambda kv: -len(kv[0])):
            text = text.replace(real, self.alias(real, prefix))
        return IP_RE.sub(lambda m: self.alias(m.group(0), "ip"), text)

    def redact_case(self, case: dict, known: dict[str, str]) -> dict:
        out = {}
        for k, v in case.items():
            if isinstance(v, str):
                out[k] = self.redact_text(v, known)
            elif isinstance(v, list):
                out[k] = [self.redact_case(x, known) if isinstance(x, dict)
                          else self.redact_text(x, known) if isinstance(x, str) else x
                          for x in v]
            elif isinstance(v, dict):
                out[k] = self.redact_case(v, known)
            else:
                out[k] = v
        return out
