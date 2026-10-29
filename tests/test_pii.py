"""tests/test_pii.py — scoreboard dedup + field mapping + pattern detection."""
import pytest
from redcheck.pii import Scoreboard, PII_CLASSES, FIELD_CLASS, _is_ciphertext


# ---------------------------------------------------------------------------
# _is_ciphertext
# ---------------------------------------------------------------------------
def test_ciphertext_enc_prefix():
    assert _is_ciphertext("enc:v1:key123:nonce:ciphertext")

def test_ciphertext_tok_prefix():
    assert _is_ciphertext("tok:v1:opaquetoken")

def test_not_ciphertext():
    assert not _is_ciphertext("1234567890123456")
    assert not _is_ciphertext("user@example.com")


# ---------------------------------------------------------------------------
# Scoreboard dedup
# ---------------------------------------------------------------------------
def test_dedup_same_value():
    sb = Scoreboard()
    sb.ingest_value("nik", "3374012345670001")
    sb.ingest_value("nik", "3374012345670001")
    sb.ingest_value("nik", "3374012345670001")
    assert sb.totals()["nik"] == 1

def test_dedup_different_values():
    sb = Scoreboard()
    sb.ingest_value("nik", "3374012345670001")
    sb.ingest_value("nik", "3374012345670002")
    assert sb.totals()["nik"] == 2

def test_ciphertext_not_counted():
    sb = Scoreboard()
    sb.ingest_value("nik", "enc:v1:dek-1:AAAA:BBBB")
    sb.ingest_value("rekening", "tok:v1:opaque123")
    assert sb.totals()["nik"] == 0
    assert sb.totals()["rekening"] == 0

def test_all_pii_classes_in_totals():
    sb = Scoreboard()
    totals = sb.totals()
    for cls in PII_CLASSES:
        assert cls in totals

def test_ingest_field_mapping():
    sb = Scoreboard()
    sb.ingest_field("no_ktp", "3374012345670001")
    sb.ingest_field("handphone", "08123456789")
    sb.ingest_field("email", "a@b.com")
    t = sb.totals()
    assert t["nik"] == 1
    assert t["hp"] == 1
    assert t["email"] == 1

def test_scan_text_nik():
    sb = Scoreboard()
    found = sb.scan_text("Anggota dengan NIK: 3374012345670001 hadir")
    assert "nik" in found
    assert sb.totals()["nik"] == 1

def test_scan_text_email():
    sb = Scoreboard()
    sb.scan_text("Hubungi di budi@dpr.go.id untuk info")
    assert sb.totals()["email"] == 1

def test_scan_text_religion():
    sb = Scoreboard()
    sb.scan_text("Agama: Islam")
    assert sb.totals()["agama"] == 1

def test_merge():
    sb1 = Scoreboard()
    sb2 = Scoreboard()
    sb1.ingest_value("nik", "3374012345670001")
    sb2.ingest_value("nik", "3374012345670001")
    sb2.ingest_value("nik", "3374012345670002")
    sb1.merge(sb2)
    assert sb1.totals()["nik"] == 2

def test_scan_json_walks_nested():
    sb = Scoreboard()
    obj = {
        "data": [
            {"nik": "3374012345670001", "full_name": "Budi"},
            {"account_no": "1234567890", "full_name": "Siti"},
        ]
    }
    sb.scan_json(obj)
    assert sb.totals()["nik"] >= 1
    assert sb.totals()["rekening"] >= 1
