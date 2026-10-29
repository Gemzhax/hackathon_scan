"""redcheck/checks/modern_p360.py — B1–B16 checks against Parlemen360 (http://localhost:3000).

Same conventions as legacy_simad.py.
"""
from __future__ import annotations

import base64
import hmac
import hashlib
import json
import re
import uuid
from typing import Optional

import httpx

from ..schema import Finding, Severity
from ..pii import Scoreboard
from ..accounts import by_role

_PII_FIELDS_MODERN = ["nik", "account_no", "address_jakarta", "address_region",
                       "mobile", "email", "npwp", "religion", "allergy_note",
                       "condition_note", "blood_type"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snippet(text: str, length: int = 200) -> str:
    return text[:length].replace("\n", " ").replace("\r", "")


def _body(r: httpx.Response) -> str:
    try:
        return r.text
    except Exception:
        return ""


def _json(r: httpx.Response) -> object:
    try:
        return r.json()
    except Exception:
        return {}


def _status_check(
    ok: bool, id: str, category: str, severity: Severity, endpoint: str,
    evidence: str = "", note: str = "", leaked: Optional[list[str]] = None,
    rows: int = 0,
) -> Finding:
    return Finding(
        id=id, category=category, severity=severity, endpoint=endpoint,
        status="fail" if ok else "pass",
        evidence_snippet=evidence, note=note,
        leaked_fields=leaked or [], rows_exposed=rows,
    )


def _skip(id: str, category: str, severity: Severity, endpoint: str, reason: str) -> Finding:
    return Finding(
        id=id, category=category, severity=severity, endpoint=endpoint,
        status="skip", note=reason,
    )


def _login_modern(client: httpx.Client, username: str, password: str) -> tuple[int, str]:
    """Return (status_code, jwt_token_or_empty)."""
    try:
        r = client.post("/api/auth/login", json={"username": username, "password": password})
        token = ""
        if r.status_code == 200:
            data = _json(r)
            if isinstance(data, dict):
                token = data.get("token", "") or data.get("access_token", "")
            if not token:
                # In hardened mode, token is sent in Set-Cookie: p360_session=<jwt>
                sc = r.headers.get("set-cookie", "")
                m = re.search(r"p360_session=([^;]+)", sc)
                if m:
                    token = m.group(1)
                elif "p360_session" in client.cookies:
                    token = client.cookies["p360_session"]
        return r.status_code, token
    except Exception:
        return 0, ""


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


# ---------------------------------------------------------------------------
# B1 — SQL injection on /api/members?q= and ?sort=
# ---------------------------------------------------------------------------
def check_B1(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B1"
    cat = "SQL Injection (/api/members?q= / ?sort=)"
    sev: Severity = "critical"
    ep  = "/api/members?q="

    try:
        r_err  = client.get("/api/members", params={"q": "'"})
        r_sort = client.get("/api/members", params={"sort": "name; DROP TABLE--"})
        r_bool_t = client.get("/api/members", params={"q": "' OR '1'='1"})
        r_bool_f = client.get("/api/members", params={"q": "' AND '1'='2"})
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body_err   = _body(r_err)
    body_bool_t = _body(r_bool_t)
    body_bool_f = _body(r_bool_f)

    has_sql_err = bool(re.search(
        r"(syntax error|pg_query|PG::SyntaxError|ERROR:|position:)",
        body_err, re.IGNORECASE,
    ))
    # Boolean diff: true returns more items
    try:
        jt = _json(r_bool_t)
        jf = _json(r_bool_f)
        bt_len = len(jt) if isinstance(jt, list) else (len(jt.get("data", [])) if isinstance(jt, dict) else 0)
        bf_len = len(jf) if isinstance(jf, list) else (len(jf.get("data", [])) if isinstance(jf, dict) else 0)
        bool_diff = bt_len > bf_len + 2
    except Exception:
        bool_diff = False

    sb.scan_text(body_bool_t)

    vuln = has_sql_err or bool_diff
    evidence = f"sql_err={has_sql_err} bool_diff={bool_diff}"
    if has_sql_err:
        m = re.search(r"(syntax error[^\n]{0,100})", body_err, re.IGNORECASE)
        evidence = m.group(1) if m else evidence
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# B2 — Excessive data exposure: /api/members returns full PII to public
# ---------------------------------------------------------------------------
def check_B2(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B2"
    cat = "Excessive data exposure (/api/members public)"
    sev: Severity = "critical"
    ep  = "/api/members"

    try:
        r = client.get("/api/members")
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    data = _json(r)
    body = _body(r)

    # Walk all items looking for PII fields — handle pagination wrapper {items:[...]}
    sensitive_found: list[str] = []
    if isinstance(data, list):
        items = data[:10]
    elif isinstance(data, dict):
        items = (data.get("items") or data.get("data") or
                 data.get("members") or data.get("rows") or [])[:10]
    else:
        items = []

    for item in items:
        if isinstance(item, dict):
            for pf in _PII_FIELDS_MODERN:
                if pf in item and item[pf] not in (None, "", []):
                    val = str(item[pf])
                    if not val.startswith(("enc:", "tok:")):
                        if pf not in sensitive_found:
                            sensitive_found.append(pf)
                        sb.ingest_field(pf, val)

    rows = len(data) if isinstance(data, list) else len(items)
    vuln = len(sensitive_found) > 0
    evidence = f"PII fields in public response: {sensitive_found[:8]} rows~{rows}"
    return _status_check(vuln, id_, cat, sev, ep, evidence, leaked=sensitive_found, rows=rows)


# ---------------------------------------------------------------------------
# B3 — BOLA / IDOR on /api/members/:id without auth
# ---------------------------------------------------------------------------
def check_B3(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B3"
    cat = "BOLA/IDOR (/api/members/:id tanpa auth)"
    sev: Severity = "critical"
    ep  = "/api/members/1"

    try:
        r = client.get("/api/members/1")
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    data = _json(r)
    body = _body(r)
    pii_found: list[str] = []

    if isinstance(data, dict):
        for pf in _PII_FIELDS_MODERN:
            if pf in data and data[pf] not in (None, "", []):
                val = str(data[pf])
                if not val.startswith(("enc:", "tok:")):
                    pii_found.append(pf)
                    sb.ingest_field(pf, val)

    vuln = r.status_code == 200 and len(pii_found) > 0
    evidence = f"status={r.status_code} pii_found={pii_found}"
    return _status_check(vuln, id_, cat, sev, ep, evidence, leaked=pii_found)


# ---------------------------------------------------------------------------
# B4 — Broken function-level auth: /api/finance, /api/health-records, /api/admin/*
# ---------------------------------------------------------------------------
def check_B4(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B4"
    cat = "Broken function-level auth (/api/finance, /api/health-records)"
    sev: Severity = "high"
    ep  = "/api/finance, /api/health-records, /api/admin/*"

    # Login as humas (shouldn't see finance/health)
    acc = by_role("humas")
    _, token = _login_modern(client, acc.username, acc.password)
    ah = _auth_header(token)

    violations: list[str] = []
    try:
        for path in ["/api/finance", "/api/health-records", "/api/admin/users"]:
            r = client.get(path, headers=ah)
            if r.status_code == 200:
                violations.append(f"{path} -> 200")
        # /api/admin/* without login (must be unauthenticated client)
        from ..client import make_client as _mc
        tmp_anon = _mc(base_url=str(client.base_url).rstrip("/"))
        r_anon = tmp_anon.get("/api/admin/export")
        if r_anon.status_code == 200:
            violations.append("/api/admin/export -> 200(anon)")
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    vuln = len(violations) > 0
    evidence = f"violations={violations}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# B5 — Export without auth
# ---------------------------------------------------------------------------
def check_B5(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B5"
    cat = "Ekspor tanpa autentikasi (/api/admin/export)"
    sev: Severity = "critical"
    ep  = "/api/admin/export"

    try:
        from ..client import make_client as _mc
        tmp_anon = _mc(base_url=str(client.base_url).rstrip("/"))
        r = tmp_anon.get("/api/admin/export")
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body = _body(r)
    is_data = r.status_code == 200 and len(body) > 100
    is_csv  = "text/csv" in r.headers.get("content-type", "").lower()

    sb.scan_text(body)

    rows = len(body.splitlines()) - 1 if is_csv else 0
    vuln = is_data
    evidence = f"status={r.status_code} len={len(body)} is_csv={is_csv} rows~{rows}"
    return _status_check(vuln, id_, cat, sev, ep, evidence, rows=rows)


# ---------------------------------------------------------------------------
# B6 — Mass assignment: PATCH /api/me with role=admin
# ---------------------------------------------------------------------------
def check_B6(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B6"
    cat = "Mass assignment (PATCH /api/me {role:admin})"
    sev: Severity = "critical"
    ep  = "/api/me"

    acc = by_role("humas")
    _, token = _login_modern(client, acc.username, acc.password)
    if not token:
        return _skip(id_, cat, sev, ep, "Login failed — target may be down")

    ah = _auth_header(token)
    try:
        r = client.patch("/api/me", json={"role": "admin"}, headers=ah)
        data = _json(r)
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    role_changed = False
    if isinstance(data, dict):
        role_changed = data.get("role") == "admin" or data.get("user", {}).get("role") == "admin"
        # If role changed (vuln mode), immediately restore original role so DB state stays clean
        if role_changed:
            try:
                client.patch("/api/me", json={"role": "humas"}, headers=ah)
            except Exception:
                pass

    vuln = role_changed
    evidence = f"status={r.status_code} role_in_response={data!r}"[:200]
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# B7 — JWT weak secret + localStorage
# ---------------------------------------------------------------------------
def check_B7(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B7"
    cat = "JWT HS256 secret lemah + token di localStorage"
    sev: Severity = "high"
    ep  = "/api/auth/login"

    acc = by_role("admin")
    _, token = _login_modern(client, acc.username, acc.password)
    if not token:
        return _skip(id_, cat, sev, ep, "Login failed — target may be down")

    # Verify with known weak secret "parlemen360"
    weak_secret = b"parlemen360"
    vuln = False
    evidence = ""
    try:
        parts = token.split(".")
        if len(parts) == 3:
            header_b64, payload_b64, sig_b64 = parts
            # Pad base64
            def _pad(s: str) -> bytes:
                s += "=" * (-len(s) % 4)
                return base64.urlsafe_b64decode(s)

            signing_input = f"{header_b64}.{payload_b64}".encode()
            expected_sig = hmac.new(weak_secret, signing_input, hashlib.sha256).digest()
            actual_sig   = _pad(sig_b64)
            vuln = hmac.compare_digest(expected_sig, actual_sig)
            evidence = f"JWT sig matches weak secret 'parlemen360' = {vuln}"

            # Decode payload for expiry check
            payload_json = _pad(payload_b64)
            payload_data = json.loads(payload_json)
            exp = payload_data.get("exp", 0)
            import time
            iat = payload_data.get("iat", 0)
            if exp and iat:
                ttl_days = (exp - iat) / 86400
                if ttl_days > 1:
                    vuln = True
                    evidence += f" TTL={ttl_days:.0f}d"
    except Exception as exc:
        evidence = f"JWT parse error: {exc}"

    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# B8 — Stored XSS via /api/members/:id/activities notes field
# ---------------------------------------------------------------------------
def check_B8(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B8"
    cat = "Stored XSS (/api/members/:id/activities notes)"
    sev: Severity = "high"
    ep  = "/api/members/1/activities"

    marker = f"<!--rc:{uuid.uuid4().hex[:8]}-->"

    acc = by_role("sdm")
    _, token = _login_modern(client, acc.username, acc.password)
    ah = _auth_header(token)

    try:
        # Inject marker — title is required by DB constraint
        r_post = client.post(
            "/api/members/1/activities",
            json={"notes": marker, "type": "meeting", "title": "RedCheck-probe"},
            headers=ah,
        )
        if r_post.status_code not in (200, 201):
            return _skip(id_, cat, sev, ep, f"POST failed {r_post.status_code}: {r_post.text[:100]}")

        # Fetch activities — may be wrapped in {items:[...]}
        r_get = client.get("/api/members/1/activities", headers=ah)
        body_get = _body(r_get)
        # Check raw body string for marker (works regardless of wrapping)
        rendered_raw = marker in body_get
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    vuln = rendered_raw
    evidence = f"marker={marker!r} rendered_raw={rendered_raw}"
    return _status_check(vuln, id_, cat, sev, ep, evidence,
                         note="State mutation — run 'make reset' to clean")


# ---------------------------------------------------------------------------
# B9 — Secrets exposed: /.env and /api/debug
# ---------------------------------------------------------------------------
def check_B9(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B9"
    cat = "Rahasia terekspos (/.env, /api/debug)"
    sev: Severity = "critical"
    ep  = "/.env, /api/debug"

    found: list[str] = []
    try:
        for path in ["/.env", "/api/debug"]:
            r = client.get(path)
            if r.status_code == 200:
                body = _body(r)
                if any(k in body for k in ("DATABASE_URL", "JWT_SECRET", "DB_PASSWORD", "SECRET")):
                    found.append(path)
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    vuln = len(found) > 0
    evidence = f"exposed_paths={found}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# B10 — PII in logs (read host-mounted log file)
# ---------------------------------------------------------------------------
def check_B10(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B10"
    cat = "PII di log (web-modern/logs/app.log)"
    sev: Severity = "high"
    ep  = "web-modern/logs/app.log (host mount)"

    from ..config import MODERN_LOG_PATH

    if not MODERN_LOG_PATH.exists():
        return _skip(id_, cat, sev, ep, f"Log not found at {MODERN_LOG_PATH} (Docker not running?)")

    try:
        # Read last 30 recent log lines
        lines = [line.strip() for line in MODERN_LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()][-30:]
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    parsed_entries: list[dict] = []
    for l in lines:
        try:
            parsed_entries.append(json.loads(l))
        except Exception:
            pass

    has_body = any("body" in e for e in parsed_entries)
    has_response = any("response" in e for e in parsed_entries)
    recent_text = "\n".join(lines)
    pii_in_log = sb.scan_text(recent_text) if (has_body or has_response) else {}

    vuln = has_body or has_response or len(pii_in_log) > 0
    evidence = f"recent_entries={len(parsed_entries)} has_body={has_body} has_response={has_response} pii_classes={list(pii_in_log.keys())}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# B11 — Verbose errors
# ---------------------------------------------------------------------------
def check_B11(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B11"
    cat = "Error verbose (stack/position/code)"
    sev: Severity = "medium"
    ep  = "/api/members?q="

    try:
        r = client.get("/api/members", params={"q": "'"})
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body = _body(r)
    has_verbose = bool(re.search(r"(\"stack\":|\"position\":|\"code\":\"[0-9]+|pg_query|Error:)", body))
    evidence = _snippet(body, 180) if has_verbose else ""
    return _status_check(has_verbose, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# B12 — Enumeration + brute force on /api/auth/login
# ---------------------------------------------------------------------------
def check_B12(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B12"
    cat = "Enumerasi + brute force (/api/auth/login)"
    sev: Severity = "medium"
    ep  = "/api/auth/login"

    try:
        import time
        # Timing difference between known and unknown user
        t0 = time.monotonic()
        r_known   = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        t1 = time.monotonic()
        r_unknown = client.post("/api/auth/login", json={"username": "noexist_xxx", "password": "wrong"})
        t2 = time.monotonic()

        b_known   = _body(r_known).lower()
        b_unknown = _body(r_unknown).lower()
        diff_msg = b_known != b_unknown

        # Timing difference > 200ms suggests no dummy bcrypt
        time_known   = (t1 - t0) * 1000
        time_unknown = (t2 - t1) * 1000
        time_diff_ms = abs(time_known - time_unknown)

        # Rate limiting: 6 attempts (use probe username so demo accounts are not locked out)
        blocked = False
        for i in range(6):
            r = client.post("/api/auth/login", json={"username": "probe_ratelimit", "password": f"bad{i}"})
            if r.status_code == 429:
                blocked = True
                break
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    vuln = diff_msg or not blocked or time_diff_ms > 300
    evidence = (f"diff_msg={diff_msg} blocked_at_6={blocked} "
                f"timing_diff_ms={time_diff_ms:.0f}")
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# B13 — Security headers + CORS + cache
# ---------------------------------------------------------------------------
def check_B13(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B13"
    cat = "Header keamanan / cache / CORS"
    sev: Severity = "medium"
    ep  = "/api/members (headers)"

    try:
        r = client.get("/api/members")
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    headers = {k.lower(): v for k, v in r.headers.items()}
    cors_wildcard = headers.get("access-control-allow-origin", "") == "*"
    powered_by   = "x-powered-by" in headers
    no_csp       = "content-security-policy" not in headers
    no_cache     = "no-store" not in headers.get("cache-control", "")

    vuln = cors_wildcard or powered_by or no_csp or no_cache
    evidence = (f"cors=* {cors_wildcard} powered_by={powered_by} "
                f"no_csp={no_csp} cache_no_store={not no_cache}")
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# B14 — Sensitive aggregate: /api/stats includes religion breakdown
# ---------------------------------------------------------------------------
def check_B14(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B14"
    cat = "Agregat data sensitif (/api/stats)"
    sev: Severity = "medium"
    ep  = "/api/stats"

    try:
        r = client.get("/api/stats")
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    data = _json(r)
    body = _body(r)
    has_religion = bool(re.search(r"(agama|religion|Islam|Kristen)", body, re.IGNORECASE))
    if isinstance(data, dict):
        has_religion = has_religion or "religion" in data or "agama" in data

    vuln = r.status_code == 200 and has_religion
    evidence = f"status={r.status_code} has_religion_aggregate={has_religion}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# B15 — Excessive DB privileges (indirect: check /api/debug or .env)
# ---------------------------------------------------------------------------
def check_B15(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B15"
    cat = "Hak DB berlebih (postgres superuser)"
    sev: Severity = "medium"
    ep  = "/.env, /api/debug"

    found_super = False
    try:
        for path in ["/.env", "/api/debug"]:
            r = client.get(path)
            body = _body(r)
            if "postgres" in body.lower() and ("DATABASE_URL" in body or "superuser" in body.lower()):
                found_super = True
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    vuln = found_super
    evidence = f"superuser_credentials_found={found_super}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# B16 — PII in free-text fields (activities ref_code / notes)
# ---------------------------------------------------------------------------
def check_B16(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "B16"
    cat = "PII di field teks bebas (member_activities.ref_code / notes)"
    sev: Severity = "high"
    ep  = "/api/activities (sample)"

    acc = by_role("sdm")
    _, token = _login_modern(client, acc.username, acc.password)
    ah = _auth_header(token)

    try:
        r = client.get("/api/activities", headers=ah)
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body = _body(r)
    pii_found = sb.scan_text(body)

    # Also check ref_code NIK pattern (16-digit)
    nik_in_ref = bool(re.search(r'"ref_code"\s*:\s*"\d{16}"', body))
    if nik_in_ref:
        pii_found["nik"] = pii_found.get("nik", []) + ["(ref_code)"]

    vuln = len(pii_found) > 0
    evidence = f"pii_in_activities={list(pii_found.keys())}"
    return _status_check(vuln, id_, cat, sev, ep, evidence,
                         note="Honeypot data trap: free-text fields require Palmerah Shield encryption/tokenization")


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_B1, check_B2, check_B3, check_B4, check_B5, check_B6,
    check_B7, check_B8, check_B9, check_B10, check_B11, check_B12,
    check_B13, check_B14, check_B15, check_B16,
]


def run_all(client: httpx.Client, sb: Scoreboard) -> list[Finding]:
    findings: list[Finding] = []
    for fn in ALL_CHECKS:
        try:
            f = fn(client, sb)
            print(f"  [{f.status.upper():4}] {f.id} {f.category}")
            findings.append(f)
        except SystemExit:
            raise
        except Exception as exc:
            fid = fn.__name__.replace("check_", "")
            print(f"  [ERR ] {fid} — {exc}")
            findings.append(Finding(
                id=fid, category="(error)", severity="info",
                endpoint="?", status="skip", note=str(exc),
            ))
    return findings
