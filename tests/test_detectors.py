"""tests/test_detectors.py — unit tests for each check using synthetic fixtures.

We mock httpx.Client so no network is needed.
Each detector is tested with a vuln fixture (expect fail) and a hardened
fixture (expect pass or skip).
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from redcheck.pii import Scoreboard
from redcheck.schema import Finding


# ---------------------------------------------------------------------------
# Fixture loader helpers
# ---------------------------------------------------------------------------
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _load(name: str) -> str:
    p = FIXTURES_DIR / name
    if p.exists():
        return p.read_text(encoding="utf-8")
    return ""


def _mock_response(body: str, status: int = 200, headers: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = MagicMock()
    r.url.path = "/test"
    try:
        r.json.return_value = json.loads(body)
    except Exception:
        r.json.return_value = {}
    return r


def _client(responses: dict[str, MagicMock]) -> MagicMock:
    """Create a mock httpx.Client where get/post/patch return from responses dict."""
    client = MagicMock()

    def _get(path, **kwargs):
        params = kwargs.get("params", {})
        q = params.get("q", params.get("sort", "")) if params else ""
        key = f"GET {path}"
        if q:
            key = f"GET {path}?q={q}"
        return responses.get(key, responses.get(f"GET {path}", _mock_response("{}", 404)))

    def _post(path, **kwargs):
        return responses.get(f"POST {path}", _mock_response("{}", 200))

    def _patch(path, **kwargs):
        return responses.get(f"PATCH {path}", _mock_response("{}", 200))

    client.get.side_effect = _get
    client.post.side_effect = _post
    client.patch.side_effect = _patch
    return client


# ===========================================================================
# A1 — SQL injection
# ===========================================================================
class TestA1:
    def test_vuln(self):
        from redcheck.checks.legacy_simad import check_A1
        body_err = "You have an error in your SQL syntax; check the manual"
        responses = {
            "GET /direktori.php?q='": _mock_response(body_err),
            "GET /direktori.php": _mock_response("<tr><tr><tr>"),
        }
        client = _client(responses)
        client.get.side_effect = lambda path, **kw: (
            _mock_response(body_err) if kw.get("params", {}).get("q") == "'"
            else _mock_response("<tr>"*5 if "1'='1" in str(kw.get("params","")) else "<tr>")
        )
        sb = Scoreboard()
        f = check_A1(client, sb)
        assert f.status == "fail"

    def test_hardened(self):
        from redcheck.checks.legacy_simad import check_A1
        safe_body = "<html><body>hasil pencarian</body></html>"
        client = _client({})
        client.get.return_value = _mock_response(safe_body)
        sb = Scoreboard()
        f = check_A1(client, sb)
        assert f.status in ("pass", "skip")

    def test_skip_on_connection_error(self):
        from redcheck.checks.legacy_simad import check_A1
        client = MagicMock()
        client.get.side_effect = Exception("Connection refused")
        sb = Scoreboard()
        f = check_A1(client, sb)
        assert f.status == "skip"


# ===========================================================================
# A6 — Hidden fields
# ===========================================================================
class TestA6:
    def test_vuln_sembunyi(self):
        from redcheck.checks.legacy_simad import check_A6
        body = '<div class="sembunyi">NIK: 3374012345670001</div>'
        client = _client({"GET /anggota.php": _mock_response(body)})
        sb = Scoreboard()
        f = check_A6(client, sb)
        assert f.status == "fail"

    def test_vuln_data_record(self):
        from redcheck.checks.legacy_simad import check_A6
        body = '<tr data-record=\'{"no_ktp":"3374012345670001"}\'></tr>'
        client = MagicMock()
        client.get.return_value = _mock_response(body)
        sb = Scoreboard()
        f = check_A6(client, sb)
        assert f.status == "fail"

    def test_hardened(self):
        from redcheck.checks.legacy_simad import check_A6
        body = "<html><table><tr><td>Budi</td></tr></table></html>"
        client = MagicMock()
        client.get.return_value = _mock_response(body)
        sb = Scoreboard()
        f = check_A6(client, sb)
        assert f.status == "pass"


# ===========================================================================
# A9 — Sensitive files
# ===========================================================================
class TestA9:
    def test_vuln_env_file(self):
        from redcheck.checks.legacy_simad import check_A9
        def _get(path, **kw):
            if path == "/.env":
                return _mock_response("DB_PASSWORD=secret\nDB_USER=root\n")
            return _mock_response("", 404)
        client = MagicMock()
        client.get.side_effect = _get
        sb = Scoreboard()
        f = check_A9(client, sb)
        assert f.status == "fail"

    def test_hardened_not_found(self):
        from redcheck.checks.legacy_simad import check_A9
        client = MagicMock()
        client.get.return_value = _mock_response("", 404)
        sb = Scoreboard()
        f = check_A9(client, sb)
        assert f.status == "pass"


# ===========================================================================
# A13 — Security headers
# ===========================================================================
class TestA13:
    def test_vuln_missing_headers(self):
        from redcheck.checks.legacy_simad import check_A13
        r = _mock_response("<html></html>", headers={"x-powered-by": "PHP/8.3"})
        client = MagicMock()
        client.get.return_value = r
        sb = Scoreboard()
        f = check_A13(client, sb)
        assert f.status == "fail"

    def test_hardened_headers_present(self):
        from redcheck.checks.legacy_simad import check_A13
        headers = {
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
        }
        r = _mock_response("<html></html>", headers=headers)
        client = MagicMock()
        client.get.return_value = r
        sb = Scoreboard()
        f = check_A13(client, sb)
        assert f.status == "pass"


# ===========================================================================
# B2 — Excessive data exposure
# ===========================================================================
class TestB2:
    def test_vuln_pii_in_response(self):
        from redcheck.checks.modern_p360 import check_B2
        data = [
            {"id": 1, "full_name": "Budi", "nik": "3374012345670001", "account_no": "1234567890"},
            {"id": 2, "full_name": "Siti", "nik": "3374012345670002", "account_no": "0987654321"},
        ]
        r = _mock_response(json.dumps(data))
        client = MagicMock()
        client.get.return_value = r
        sb = Scoreboard()
        f = check_B2(client, sb)
        assert f.status == "fail"
        assert sb.totals()["nik"] >= 2
        assert sb.totals()["rekening"] >= 2

    def test_hardened_ciphertext(self):
        from redcheck.checks.modern_p360 import check_B2
        data = [
            {"id": 1, "full_name": "Budi", "nik": "enc:v1:key:nonce:ct", "account_no": "tok:v1:opaque"},
        ]
        r = _mock_response(json.dumps(data))
        client = MagicMock()
        client.get.return_value = r
        sb = Scoreboard()
        f = check_B2(client, sb)
        assert f.status == "pass"
        assert sb.totals()["nik"] == 0

    def test_hardened_fields_absent(self):
        from redcheck.checks.modern_p360 import check_B2
        data = [{"id": 1, "full_name": "Budi", "room_code": "A1"}]
        r = _mock_response(json.dumps(data))
        client = MagicMock()
        client.get.return_value = r
        sb = Scoreboard()
        f = check_B2(client, sb)
        assert f.status == "pass"


# ===========================================================================
# B7 — JWT weak secret
# ===========================================================================
class TestB7:
    def test_vuln_weak_secret(self):
        import base64, hmac, hashlib, json as _json
        from redcheck.checks.modern_p360 import check_B7

        secret = b"parlemen360"
        header  = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"1","iat":1700000000,"exp":1702592000}').rstrip(b"=").decode()
        sig_bytes = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
        sig = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
        token = f"{header}.{payload}.{sig}"

        post_r = _mock_response(_json.dumps({"token": token}))
        client = MagicMock()
        client.post.return_value = post_r
        sb = Scoreboard()
        f = check_B7(client, sb)
        assert f.status == "fail"

    def test_hardened_wrong_secret(self):
        import base64, hmac, hashlib, json as _json
        from redcheck.checks.modern_p360 import check_B7

        # Token signed with strong random secret — won't match "parlemen360"
        secret = b"very-random-secret-key-32bytes-x"
        header  = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"1","iat":1700000000,"exp":1700001800}').rstrip(b"=").decode()
        sig_bytes = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
        sig = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
        token = f"{header}.{payload}.{sig}"

        post_r = _mock_response(_json.dumps({"token": token}))
        client = MagicMock()
        client.post.return_value = post_r
        sb = Scoreboard()
        f = check_B7(client, sb)
        assert f.status == "pass"


# ===========================================================================
# B9 — Secrets exposed
# ===========================================================================
class TestB9:
    def test_vuln_env_exposed(self):
        from redcheck.checks.modern_p360 import check_B9
        def _get(path, **kw):
            if path == "/.env":
                return _mock_response("DATABASE_URL=postgres://postgres:secret@localhost/parlemen360\nJWT_SECRET=parlemen360\n")
            return _mock_response("", 404)
        client = MagicMock()
        client.get.side_effect = _get
        sb = Scoreboard()
        f = check_B9(client, sb)
        assert f.status == "fail"

    def test_hardened_404(self):
        from redcheck.checks.modern_p360 import check_B9
        client = MagicMock()
        client.get.return_value = _mock_response("", 404)
        sb = Scoreboard()
        f = check_B9(client, sb)
        assert f.status == "pass"


# ===========================================================================
# B13 — CORS wildcard
# ===========================================================================
class TestB13:
    def test_vuln_cors_wildcard(self):
        from redcheck.checks.modern_p360 import check_B13
        r = _mock_response("[]", headers={
            "access-control-allow-origin": "*",
            "x-powered-by": "Express",
        })
        client = MagicMock()
        client.get.return_value = r
        sb = Scoreboard()
        f = check_B13(client, sb)
        assert f.status == "fail"

    def test_hardened_strict_origin(self):
        from redcheck.checks.modern_p360 import check_B13
        r = _mock_response("[]", headers={
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "cache-control": "no-store",
            "access-control-allow-origin": "http://localhost:3000",
        })
        client = MagicMock()
        client.get.return_value = r
        sb = Scoreboard()
        f = check_B13(client, sb)
        assert f.status == "pass"
