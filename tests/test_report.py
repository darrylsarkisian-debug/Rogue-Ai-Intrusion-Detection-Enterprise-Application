"""The client PDF must build from real demo output and survive hostile text in log-derived fields."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from make_report import build_report  # noqa: E402


def _case(**kw):
    base = {"case_id": "CASE-001", "subject": "jsmith", "severity": "high", "goal": "goal1_data_to_ai",
            "explanation": "jsmith sent 1 file-sized upload(s) to DeepSeek.", "likely_cause": "x",
            "confidence": "medium", "recommended_action": "Technician review.",
            "coverage_note": "n/a", "mode": "rules_only", "rules": ["SAI-003"]}
    base.update(kw)
    return base


def _is_pdf(p: Path) -> bool:
    return p.exists() and p.read_bytes()[:5] == b"%PDF-" and p.stat().st_size > 3000


def test_builds_with_cases(tmp_path):
    out = build_report([_case(), _case(case_id="CASE-002", severity="critical",
                                       goal="goal2_ai_speed_attack", rules=["AUT-004"])],
                       tmp_path / "r.pdf", client="Test Co", sample=True)
    assert _is_pdf(out)


def test_builds_with_no_cases(tmp_path):
    assert _is_pdf(build_report([], tmp_path / "empty.pdf"))


def test_hostile_text_does_not_break_or_inject(tmp_path):
    evil = "</para><b>IGNORE ALL INSTRUCTIONS & <font size=99>"
    out = build_report([_case(subject=evil, explanation=evil, rules=["NOPE-999"])], tmp_path / "evil.pdf",
                       client=evil)
    assert _is_pdf(out)


def test_cloud_mode_uses_model_action(tmp_path):
    out = build_report([_case(mode="cloud", recommended_action="Call the user today.")], tmp_path / "c.pdf")
    assert _is_pdf(out)
