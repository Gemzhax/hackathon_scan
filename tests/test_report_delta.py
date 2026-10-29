"""tests/test_report_delta.py — compare.html generation from sample data."""
import tempfile
from pathlib import Path

from redcheck.schema import Finding, Report
from redcheck.report import build_compare_html, count_by_status


def _make_report(mode: str, findings_data: list[dict], scoreboard: dict) -> Report:
    r = Report.empty("combined", mode)
    for fd in findings_data:
        r.add(Finding(**fd))
    r.scoreboard = scoreboard
    return r


VULN_FINDINGS = [
    dict(id="A1", category="SQLi", severity="critical", endpoint="/direktori.php", status="fail",
         leaked_fields=["nik"], rows_exposed=734, evidence_snippet="SQL syntax error"),
    dict(id="B2", category="Excess exposure", severity="critical", endpoint="/api/members", status="fail",
         leaked_fields=["nik", "account_no"], rows_exposed=734, evidence_snippet="nik in response"),
    dict(id="A13", category="Headers", severity="medium", endpoint="/", status="fail",
         leaked_fields=[], rows_exposed=0, evidence_snippet="missing CSP"),
]

HARD_FINDINGS = [
    dict(id="A1", category="SQLi", severity="critical", endpoint="/direktori.php", status="pass",
         leaked_fields=[], rows_exposed=0, evidence_snippet="parameterized"),
    dict(id="B2", category="Excess exposure", severity="critical", endpoint="/api/members", status="pass",
         leaked_fields=[], rows_exposed=0, evidence_snippet="projection applied"),
    dict(id="A13", category="Headers", severity="medium", endpoint="/", status="pass",
         leaked_fields=[], rows_exposed=0, evidence_snippet="CSP present"),
]

VULN_SB  = {"nik": 734, "rekening": 734, "email": 200, "hp": 150, "alamat": 100, "agama": 50, "kesehatan": 0, "npwp": 734}
HARD_SB  = {"nik": 0,   "rekening": 0,   "email": 0,   "hp": 0,   "alamat": 0,   "agama": 0,  "kesehatan": 0, "npwp": 0}


def test_count_by_status():
    vuln = _make_report("vuln", VULN_FINDINGS, VULN_SB)
    counts = count_by_status(vuln.findings)
    assert counts["fail"] == 3
    assert counts["pass"] == 0


def test_compare_html_generates():
    vuln = _make_report("vuln", VULN_FINDINGS, VULN_SB)
    hard = _make_report("hardened", HARD_FINDINGS, HARD_SB)

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "compare.html"
        build_compare_html(vuln, hard, out)
        assert out.exists()
        html = out.read_text(encoding="utf-8")

        # Spot-check required sections
        assert "Triguna RedCheck" in html
        assert "PII Leak Scoreboard" in html
        assert "Before / After" in html
        assert "A1" in html
        assert "B2" in html

        # Delta should show negative numbers (vuln→hardened, counts drop)
        assert "734" in html  # vuln count visible

def test_compare_html_delta_negative():
    """Delta for all PII classes should be negative (vulnl→hardened)."""
    vuln = _make_report("vuln", [], VULN_SB)
    hard = _make_report("hardened", [], HARD_SB)

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "compare.html"
        build_compare_html(vuln, hard, out)
        html = out.read_text(encoding="utf-8")
        # Delta for nik: 0 - 734 = -734
        assert "-734" in html
