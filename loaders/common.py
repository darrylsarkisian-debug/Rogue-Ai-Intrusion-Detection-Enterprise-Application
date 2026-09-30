"""Small helpers shared by the M365 and Google loaders."""
from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def to_ts(value) -> str:
    """Normalise ISO-8601 / US 'M/D/YYYY h:mm:ss AM' timestamps to 'YYYY-MM-DD HH:MM:SS' UTC."""
    if value in (None, ""):
        return ""
    s = str(value).strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                dt = None
        if dt is None:
            return ""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def clean_ip(value) -> str:
    """Strip ports and brackets: '203.0.113.5:443', '[2001:db8::1]:443' -> bare address."""
    s = str(value or "").strip()
    if s.startswith("["):
        return s[1:].split("]")[0]
    if s.count(":") == 1 and "." in s:
        return s.split(":")[0]
    return s


def read_records(path) -> list[dict]:
    """Read a JSON list, JSON object with 'value'/'items'/'records', JSON Lines, or CSV."""
    p = Path(path)
    text = p.read_text(encoding="utf-8-sig")
    if p.suffix.lower() == ".csv":
        return list(csv.DictReader(text.splitlines()))
    stripped = text.lstrip()
    if not stripped:
        return []
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:  # JSON Lines
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, list):
        return data
    for key in ("value", "items", "records", "Records"):
        if isinstance(data, dict) and isinstance(data.get(key), list):
            return data[key]
    return [data]


def ci_get(row: dict, *names, default=""):
    """Case-insensitive, space/underscore-insensitive dict lookup (CSV header drift)."""
    norm = {re.sub(r"[\s_]+", "", k).lower(): v for k, v in row.items()}
    for n in names:
        v = norm.get(re.sub(r"[\s_]+", "", n).lower())
        if v not in (None, ""):
            return v
    return default


def as_obj(value):
    """Return a dict/list whether the value is already parsed or a JSON string."""
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str) and value.strip()[:1] in "{[":
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return None
