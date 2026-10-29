"""tests/test_schema.py — Finding & Report dataclasses + JSON round-trip."""
import json
import tempfile
from pathlib import Path
from redcheck.schema import Finding, Report, load_report


def _make_finding(id: str, status="fail") -> Finding:
    return Finding(
        id=id, category="Test cat", severity="high",
        endpoint="/test", status=status,
        leaked_fields=["nik"], rows_exposed=5,
        evidence_snippet="sql error detected",
    )


def test_finding_fields():
    f = _make_finding("A1")
    assert f.id == "A1"
    assert f.status == "fail"
    assert "nik" in f.leaked_fields
    assert f.rows_exposed == 5


def test_report_add_and_dict():
    r = Report.empty("simad", "vuln")
    r.add(_make_finding("A1"))
    r.add(_make_finding("A2", "pass"))
    r.scoreboard = {"nik": 10, "rekening": 5, "email": 3,
                    "hp": 1, "alamat": 2, "agama": 0, "kesehatan": 0, "npwp": 0}

    d = r.to_dict()
    assert d["target"] == "simad"
    assert d["mode"] == "vuln"
    assert len(d["findings"]) == 2
    assert d["findings"][0]["id"] == "A1"
    assert d["scoreboard"]["nik"] == 10


def test_report_write_and_load():
    r = Report.empty("simad", "vuln")
    r.add(_make_finding("A1"))
    r.scoreboard = {"nik": 3, "rekening": 1, "email": 0,
                    "hp": 0, "alamat": 0, "agama": 0, "kesehatan": 0, "npwp": 0}

    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "test_report.json"
        r.write(p)
        assert p.exists()

        loaded = load_report(p)
        assert loaded.target == "simad"
        assert loaded.mode == "vuln"
        assert len(loaded.findings) == 1
        assert loaded.findings[0].id == "A1"
        assert loaded.scoreboard["nik"] == 3


def test_report_json_schema():
    """Verify output JSON has all required contract keys."""
    r = Report.empty("combined", "hardened")
    r.add(_make_finding("B1", "pass"))
    r.scoreboard = {"nik": 0, "rekening": 0, "email": 0,
                    "hp": 0, "alamat": 0, "agama": 0, "kesehatan": 0, "npwp": 0}
    d = r.to_dict()

    required_top = {"target", "mode", "generated_at", "findings", "scoreboard"}
    assert required_top <= set(d.keys())

    required_finding = {"id", "category", "severity", "endpoint", "leaked_fields",
                        "rows_exposed", "evidence_snippet", "status"}
    for f in d["findings"]:
        assert required_finding <= set(f.keys())
