"""Client-facing PDF findings report ("AI Exposure Assessment").

Turns data/report.json (written by run_demo.py) into a plain-English PDF an MSP can hand to its client.

Usage:
  python make_report.py                                   # data/report.json -> reports/AI_Exposure_Assessment.pdf
  python make_report.py --client "Contoso Ltd" --prepared-by "Darryl Sarkisian"
  python make_report.py --sample                          # stamps SAMPLE DATA on every page (use for the demo)

Honesty rules baked in: findings are indicators, not proof; Goal 2 is "automation-like activity",
never "an AI attacked you"; coverage limits are printed in every report.
"""
from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageBreak, PageTemplate,
                                Paragraph, Spacer, Table, TableStyle)

GOAL1, GOAL2, GOAL3 = "goal1_data_to_ai", "goal2_ai_speed_attack", "goal3_unapproved_agent"

GOALS = {
    GOAL1: ("1", "Is staff pasting company data into AI tools?",
            "Staff and AI tools",
            "We looked for visits to AI services and for uploads whose size suggests pasted text or documents. "
            "We can see how much was sent and where, not what it contained."),
    GOAL2: ("2", "Is someone attacking us with AI-speed automation?",
            "Automated attack activity",
            "We looked for logins and scans that happen faster or more uniformly than a person could manage. "
            "We report this as automation-like activity with a confidence level. We cannot prove an attacker is an AI."),
    GOAL3: ("3", "Are unapproved autonomous agents running on our systems?",
            "Unapproved AI agents and apps",
            "We looked for local AI models, agent software, servers calling AI services, and AI apps that "
            "employees connected to Microsoft 365 or Google accounts."),
}

SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}

NAVY = colors.HexColor("#1F2A44")
INK = colors.HexColor("#222222")
MUTED = colors.HexColor("#666B76")
RULE = colors.HexColor("#D9DCE3")
PANEL = colors.HexColor("#F4F5F8")
SEV_COLOR = {"critical": colors.HexColor("#9B1C1C"), "high": colors.HexColor("#B45309"),
             "medium": colors.HexColor("#8A5A00"), "low": colors.HexColor("#3B5B7A")}

# Plain-English title and suggested next step for each detection rule.
# (priority: lower = shown first when a case has several rules)
RULE_INFO = {
    "SAI-003": (1, "File-sized upload to an AI tool",
                "Ask the user what file was uploaded and whether it held client or confidential data. "
                "If it did, treat it as a data-handling incident under your policy."),
    "SAI-004": (2, "Burst of uploads to AI tools",
                "Review what was shared during the burst and who else uses the same tool."),
    "SAI-002": (3, "Paste-sized text sent to an AI tool",
                "Ask the user what was pasted. Remind staff which company data must not go into public AI tools."),
    "SAI-001": (4, "AI tool in use that is not approved",
                "Decide whether the tool should be approved. If not, point staff to an approved alternative."),
    "AUT-004": (1, "Successful login after a burst of failed attempts",
                "Reset the account's password and sign out its active sessions now. Review its recent activity, "
                "confirm multi-factor sign-in is required, and block the source address if it is external."),
    "AUT-002": (2, "One source trying many accounts",
                "Block the source address, confirm multi-factor sign-in is enforced, and check whether any of the "
                "accounts tried were later used successfully."),
    "AUT-001": (3, "Logins arriving at machine speed",
                "Check whether this is a known tool, such as a backup job or monitoring system. If not, block the source."),
    "AUT-003": (3, "Fast, wide network scan",
                "Identify the device behind the address. If it is not an approved scanner, isolate it and investigate."),
    "OAU-003": (1, "Organization-wide consent to an AI app",
                "Open the admin portal and review the app's permissions today. Revoke the consent unless it is "
                "approved, because it can act for every user."),
    "OAU-002": (2, "AI app given broad access to data",
                "Review the permissions this app holds and revoke them if the app is not approved."),
    "AGT-005": (2, "Server making repeated AI service calls",
                "Identify which application and owner is behind these calls. Confirm the API key belongs to the "
                "company and that the data being sent is allowed."),
    "AGT-001": (2, "AI software running on a company machine",
                "Confirm with the machine's owner what it is used for. Remove it, or add it to the approved "
                "registry with an owner and a reason."),
    "AGT-003": (3, "AI model file stored on a machine",
                "Confirm who downloaded it and why. Large model files usually mean local AI software is in use."),
    "AGT-002": (4, "Port typical of local AI services is open",
                "Check which program opened the port and whether it should be reachable on the network."),
    "AGT-004": (5, "Sustained heavy graphics-card use",
                "Check what is using the graphics card. This can be a local AI model or a legitimate workload."),
    "OAU-001": (3, "Employee connected an AI-looking app",
                "Ask the employee what it is used for. Approve it, or revoke access and offer an approved alternative."),
    "OAU-004": (4, "AI app spreading across employees",
                "Several employees connected the same app in a short time. Decide whether to approve it "
                "company-wide or remove it."),
}

COVERAGE_LIMITS = [
    "Personal phones, home networks, and laptops that are off the company network are not covered.",
    "We see where data went and how much, not what it contained. Pasted or uploaded content is inferred from size.",
    "Activity inside an already-approved tool that looks like normal use will not be flagged.",
    "AI-looking apps are identified by name and behavior. Apps with neutral names can be missed, and some "
    "ordinary apps can be flagged by mistake.",
    "Shared internet addresses, such as offices and VPNs, can make several people look like one source.",
    "Automation-like activity means the behavior is faster or more uniform than a person's. It does not prove "
    "that an attacker used AI.",
]


# --------------------------------------------------------------------------- helpers
def _p(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def _styles() -> dict[str, ParagraphStyle]:
    base = dict(fontName="Helvetica", textColor=INK, leading=14, fontSize=10, alignment=TA_LEFT)
    return {
        "body": ParagraphStyle("body", **base),
        "small": ParagraphStyle("small", **{**base, "fontSize": 8.5, "leading": 11, "textColor": MUTED}),
        "h1": ParagraphStyle("h1", **{**base, "fontName": "Helvetica-Bold", "fontSize": 17, "leading": 21,
                                     "textColor": NAVY, "spaceBefore": 6, "spaceAfter": 6}),
        "h2": ParagraphStyle("h2", **{**base, "fontName": "Helvetica-Bold", "fontSize": 12.5, "leading": 16,
                                     "textColor": NAVY, "spaceBefore": 10, "spaceAfter": 4}),
        "label": ParagraphStyle("label", **{**base, "fontName": "Helvetica-Bold", "fontSize": 8, "leading": 10,
                                           "textColor": MUTED}),
        "subject": ParagraphStyle("subject", **{**base, "fontName": "Helvetica-Bold", "fontSize": 11, "leading": 14}),
        "tile_n": ParagraphStyle("tile_n", **{**base, "fontName": "Helvetica-Bold", "fontSize": 22, "leading": 26,
                                             "textColor": colors.white}),
        "tile_l": ParagraphStyle("tile_l", **{**base, "fontName": "Helvetica-Bold", "fontSize": 8, "leading": 10,
                                             "textColor": colors.white}),
        "chip": ParagraphStyle("chip", **{**base, "fontName": "Helvetica-Bold", "fontSize": 8.5, "leading": 11,
                                         "textColor": colors.white}),
    }


def _rules_sorted(case: dict) -> list[str]:
    rules = [r for r in case.get("rules", []) if r in RULE_INFO]
    return sorted(rules, key=lambda r: RULE_INFO[r][0])


def _what_to_do(case: dict) -> str:
    """Cloud triage supplies its own action. Rules-only mode uses the per-rule guidance above."""
    if case.get("mode") == "cloud" and case.get("recommended_action"):
        return case["recommended_action"]
    steps = [RULE_INFO[r][2] for r in _rules_sorted(case)[:1]]
    if steps:
        return " ".join(steps)
    return case.get("recommended_action") or "Have a technician review this case."


def _headline(case: dict) -> str:
    rules = _rules_sorted(case)
    return RULE_INFO[rules[0]][1] if rules else "Finding"


def _sorted_cases(cases: list[dict]) -> list[dict]:
    return sorted(cases, key=lambda c: (-SEV_ORDER.get(c.get("severity", "low"), 0), c.get("case_id", "")))


# --------------------------------------------------------------------------- page furniture
def _make_page_decor(client: str, sample: bool, generated: str):
    def decorate(canv, doc):
        w, h = letter
        canv.saveState()
        if doc.page == 1:
            canv.setFillColor(NAVY)
            canv.rect(0, h - 1.55 * inch, w, 1.55 * inch, stroke=0, fill=1)
            canv.setFillColor(colors.white)
            canv.setFont("Helvetica-Bold", 24)
            canv.drawString(0.75 * inch, h - 0.85 * inch, "AI Exposure Assessment")
            canv.setFont("Helvetica", 11)
            canv.drawString(0.75 * inch, h - 1.15 * inch, f"Prepared for {client}")
            canv.setFont("Helvetica", 9)
            canv.drawRightString(w - 0.75 * inch, h - 1.15 * inch, generated)
        else:
            canv.setFillColor(MUTED)
            canv.setFont("Helvetica", 8.5)
            canv.drawString(0.75 * inch, h - 0.5 * inch, f"AI Exposure Assessment  |  {client}")
            canv.setStrokeColor(RULE)
            canv.line(0.75 * inch, h - 0.58 * inch, w - 0.75 * inch, h - 0.58 * inch)
        canv.setFillColor(MUTED)
        canv.setFont("Helvetica", 8)
        canv.drawString(0.75 * inch, 0.5 * inch, "Confidential. Findings are indicators for review, not proof of wrongdoing.")
        canv.drawRightString(w - 0.75 * inch, 0.5 * inch, f"Page {doc.page}")
        if sample:
            canv.setFillColor(colors.HexColor("#B45309"))
            canv.setFont("Helvetica-Bold", 8.5)
            canv.drawCentredString(w / 2, 0.72 * inch, "SAMPLE REPORT - built from simulated data, not a real client environment")
        canv.restoreState()
    return decorate


# --------------------------------------------------------------------------- sections
def _summary_tiles(cases: list[dict], st) -> Table:
    counts = {s: sum(1 for c in cases if c.get("severity") == s) for s in SEV_ORDER}
    style = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 10)]
    for i, sev in enumerate(("critical", "high", "medium", "low")):
        style.append(("BACKGROUND", (i, 0), (i, 0), SEV_COLOR[sev]))
        style.append(("LINEAFTER", (i, 0), (i, 0), 4, colors.white))
    cells2 = []
    for sev in ("critical", "high", "medium", "low"):
        cells2.append(Table([[_p(str(counts[sev]), st["tile_n"])], [_p(SEV_LABEL[sev] + " CASES", st["tile_l"])]],
                            style=[("LEFTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 0),
                                   ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
    t2 = Table([cells2], colWidths=[1.7 * inch] * 4, rowHeights=[0.85 * inch])
    t2.setStyle(TableStyle(style))
    return t2


def _questions_table(cases: list[dict], st) -> Table:
    rows = [[_p("QUESTION", st["label"]), _p("WHAT WE FOUND", st["label"]), _p("HIGHEST", st["label"])]]
    styles = [("LINEBELOW", (0, 0), (-1, 0), 0.8, NAVY), ("VALIGN", (0, 0), (-1, -1), "TOP"),
              ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
              ("LINEBELOW", (0, 1), (-1, -1), 0.4, RULE), ("LEFTPADDING", (0, 0), (-1, -1), 4)]
    for i, goal in enumerate(GOALS, start=1):
        gcases = [c for c in cases if c.get("goal") == goal]
        q = GOALS[goal][1]
        if gcases:
            top = max(gcases, key=lambda c: SEV_ORDER.get(c.get("severity", "low"), 0))["severity"]
            n = len(gcases)
            found = f"{n} case{'s' if n != 1 else ''} need review."
            chip = _p(SEV_LABEL[top], st["chip"])
            styles.append(("BACKGROUND", (2, i), (2, i), SEV_COLOR[top]))
        else:
            found, chip = "No indicators found in the data we reviewed.", _p("NONE", st["label"])
        rows.append([_p(q, st["body"]), _p(found, st["body"]), chip])
    t = Table(rows, colWidths=[3.1 * inch, 2.7 * inch, 1.2 * inch])
    styles.append(("ALIGN", (2, 1), (2, -1), "CENTER"))
    styles.append(("VALIGN", (0, 1), (-1, -1), "MIDDLE"))
    t.setStyle(TableStyle(styles))
    return t


def _case_block(case: dict, st):
    sev = case.get("severity", "low")
    rules = _rules_sorted(case)
    chip = Table([[_p(SEV_LABEL.get(sev, sev.upper()), st["chip"])]], colWidths=[0.95 * inch])
    chip.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SEV_COLOR.get(sev, MUTED)),
                              ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                              ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    meta_bits = [f"Confidence: {str(case.get('confidence', 'n/a')).capitalize()}", f"Case {case.get('case_id', '')}"]
    if rules:
        meta_bits.append("Rules: " + ", ".join(rules))
    body = [
        _p(case.get("subject", ""), st["subject"]),
        _p(_headline(case), st["label"]),
        Spacer(1, 3),
        _p("What we found", st["label"]),
        _p(case.get("explanation", ""), st["body"]),
        Spacer(1, 3),
        _p("What to do next", st["label"]),
        _p(_what_to_do(case), st["body"]),
    ]
    if case.get("mode") == "cloud" and case.get("likely_cause"):
        body += [Spacer(1, 3), _p("Most likely cause", st["label"]), _p(case["likely_cause"], st["body"])]
    body += [Spacer(1, 4), _p("  |  ".join(meta_bits), st["small"])]
    t = Table([[chip, body]], colWidths=[1.1 * inch, 5.9 * inch])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOX", (0, 0), (-1, -1), 0.6, RULE),
                           ("BACKGROUND", (1, 0), (1, 0), colors.white), ("LEFTPADDING", (0, 0), (-1, -1), 8),
                           ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    return KeepTogether([t, Spacer(1, 8)])


# --------------------------------------------------------------------------- build
def build_report(cases: list[dict], out_path: Path, client: str = "Your organization",
                 prepared_by: str = "", sample: bool = False, period: str = "") -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    st = _styles()
    generated = date.today().strftime("%B %d, %Y").replace(" 0", " ")
    doc = BaseDocTemplate(str(out_path), pagesize=letter, leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                          topMargin=0.85 * inch, bottomMargin=0.95 * inch,
                          title=f"AI Exposure Assessment - {client}", author=prepared_by or "AI Exposure Assessment")
    w, h = letter
    first = Frame(0.75 * inch, 0.95 * inch, w - 1.5 * inch, h - 1.55 * inch - 0.95 * inch - 0.25 * inch, id="first")
    later = Frame(0.75 * inch, 0.95 * inch, w - 1.5 * inch, h - 0.85 * inch - 0.95 * inch, id="later")
    decor = _make_page_decor(client, sample, generated)
    doc.addPageTemplates([PageTemplate("first", [first], onPage=decor, autoNextPageTemplate="later"),
                          PageTemplate("later", [later], onPage=decor)])

    cases = _sorted_cases(cases)
    story: list = []

    # ---- page 1: summary
    story.append(_p("Summary", st["h1"]))
    lead = (f"We reviewed activity for {escape(client)} for signs of three kinds of AI-related risk. "
            f"{len(cases)} case{'s' if len(cases) != 1 else ''} need{'s' if len(cases) == 1 else ''} attention.")
    if period:
        lead += f" Period reviewed: {escape(period)}."
    story.append(Paragraph(lead, st["body"]))
    story.append(Spacer(1, 10))
    story.append(_summary_tiles(cases, st))
    story.append(Spacer(1, 12))
    story.append(_p("Your three questions", st["h2"]))
    story.append(_questions_table(cases, st))

    story.append(_p("Do these first", st["h2"]))
    top = [c for c in cases if c.get("severity") in ("critical", "high")][:3] or cases[:3]
    if not top:
        story.append(_p("No cases were raised. Keep monitoring and review the approved-tools list quarterly.", st["body"]))
    for n, c in enumerate(top, start=1):
        story.append(Paragraph(f"<b>{n}.</b> <b>{escape(str(c.get('subject', '')))}</b>: {escape(_headline(c))}. "
                               f"{escape(_what_to_do(c))}", st["body"]))
        story.append(Spacer(1, 4))

    # ---- findings by goal
    for goal, (num, question, short, how) in GOALS.items():
        gcases = [c for c in cases if c.get("goal") == goal]
        story.append(PageBreak() if goal == GOAL1 else Spacer(1, 6))
        story.append(_p(f"{num}. {question}", st["h1"]))
        story.append(_p(how, st["small"]))
        story.append(Spacer(1, 6))
        if not gcases:
            story.append(_p("No indicators found in the data we reviewed. This is not a guarantee: see the limits of this assessment.", st["body"]))
        for c in gcases:
            story.append(_case_block(c, st))

    # ---- limits
    story.append(PageBreak())
    story.append(_p("What this assessment can and cannot see", st["h1"]))
    story.append(_p("We aim to promise visibility you can rely on, not total coverage. Please read these limits "
                    "alongside the findings.", st["body"]))
    story.append(Spacer(1, 6))
    for item in COVERAGE_LIMITS:
        story.append(Paragraph(f"&bull;&nbsp;&nbsp;{escape(item)}", ParagraphStyle(
            "li", parent=st["body"], leftIndent=14, firstLineIndent=-10, spaceAfter=5)))
    story.append(_p("How to read the confidence levels", st["h2"]))
    story.append(_p("High means the evidence is direct, such as a program found running. Medium means the pattern "
                    "strongly suggests the activity but could have an innocent cause. Low means a signal worth "
                    "knowing about but not worth acting on alone.", st["body"]))
    story.append(_p("About this report", st["h2"]))
    if any(c.get("mode") == "cloud" for c in cases):
        mode_txt = ("Findings come from fixed detection rules. An AI assistant then explained each case in plain English "
                    "using redacted summaries: names, machines, and addresses were replaced before anything left the "
                    "client network. The assistant is read-only and takes no action.")
    else:
        mode_txt = ("Findings come from fixed detection rules. No data was sent to any cloud AI service in producing "
                    "this report.")
    story.append(_p(mode_txt, st["body"]))
    if prepared_by:
        story.append(Spacer(1, 10))
        story.append(_p(f"Prepared by {prepared_by}.", st["small"]))

    doc.build(story)
    return out_path


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the client PDF findings report.")
    ap.add_argument("--in", dest="src", default="data/report.json")
    ap.add_argument("--out", default="reports/AI_Exposure_Assessment.pdf")
    ap.add_argument("--client", default="Your organization")
    ap.add_argument("--prepared-by", default="")
    ap.add_argument("--period", default="", help='e.g. "Sep 15 - Sep 29, 2026"')
    ap.add_argument("--sample", action="store_true", help="stamp SAMPLE on every page (simulated data)")
    args = ap.parse_args()
    cases = json.loads(Path(args.src).read_text(encoding="utf-8"))
    out = build_report(cases, Path(args.out), args.client, args.prepared_by, args.sample, args.period)
    print(f"Wrote {out} ({len(cases)} cases)")


if __name__ == "__main__":
    main()
