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
from ..config import BASE_SIMAD

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


def _login_simad(client: httpx.Client, username: str, password: str) -> httpx.Response:
    """Fetch CSRF token from login.php (needed in hardened mode) and POST credentials."""
    data = {"username": username, "password": password}
    try:
        r_get = client.get("/login.php")
        m = re.search(r'name=["\']csrf["\']\s+value=["\']([^"\']+)["\']', _body(r_get))
        if m:
            data["csrf"] = m.group(1)
    except Exception:
        pass
    return client.post("/login.php", data=data)


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

    # In vuln mode, numeric SQLi works and unapproved columns are hidden with class="sembunyi"
    # In hardened mode, ctype_digit returns 400 and denied columns are stripped by project() (showing "Terbatas")
    no_reject = r_alpha.status_code != 400
    has_sembunyi = "sembunyi" in body_valid
    has_sql_error = bool(re.search(r"(SQL syntax|mysql_fetch|MySQL Error)", body_inject, re.IGNORECASE))

    sb.scan_text(body_inject)
    sb.scan_text(body_valid)

    vuln = no_reject or has_sembunyi or has_sql_error
    evidence = f"no_reject_alpha_400={no_reject} (status={r_alpha.status_code}) has_sembunyi={has_sembunyi} sql_error={has_sql_error}"
    leaked = []
    if has_sembunyi:
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

    payload_user = "admin' OR '1'='1' -- "
    payload_pass = "anything"

    try:
        r = _login_simad(client, payload_user, payload_pass)
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    body = _body(r)
    # Bypass succeeded if actually redirected away from login or landed on dashboard
    redirected = r.url.path not in ("/login.php", "/login")
    has_sql_error = bool(re.search(r"(SQL syntax|mysql_fetch|MySQL Error)", body, re.IGNORECASE))
    logged_in = redirected or bool(re.search(r"(selamat datang|logout\.php)", body, re.IGNORECASE))

    # In vuln mode: login bypass redirects to dashboard or causes SQL error in query
    # In hardened mode: prepared statement treats input as literal username -> fails login on login.php
    vuln = logged_in or has_sql_error
    evidence = f"status={r.status_code} url={r.url} sql_error={has_sql_error} logged_in={logged_in}"
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
            r = _login_simad(client, "probe_brute", f"wrong{i}")
            body = _body(r).lower()
            if r.status_code in (429, 403) or "terlalu banyak" in body or "coba lagi dalam 1 menit" in body:
                blocked = True
                break
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    evidence = f"Sent {attempts} attempts, rate_limited={blocked}"
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

    # Also check for data-record leaking sensitive fields in anggota.php or direktori.php
    def _has_pii_in_data_record(text: str) -> bool:
        for m in re.finditer(r'data-record=(["\'])(.*?)\1', text, re.IGNORECASE | re.DOTALL):
            val = m.group(2)
            if any(k in val.lower() for k in ("no_ktp", "rekening", "npwp", "handphone", "alamat")):
                return True
        return False

    data_record_pii = _has_pii_in_data_record(body)
    try:
        rd = client.get("/direktori.php")
        body_d = _body(rd)
        data_record_pii = data_record_pii or _has_pii_in_data_record(body_d)
    except Exception:
        pass

    sb.scan_text(body)
    vuln = hidden_div or debug_comment or data_record_pii
    evidence = f"sembunyi={hidden_div} debug_comment={debug_comment} data_record_pii={data_record_pii}"
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

    # Try accessing without login (must not serve financial data at /keuangan.php)
    try:
        from ..client import make_client as _mc
        anon_client = _mc(base_url=str(client.base_url).rstrip("/") or BASE_SIMAD)
        r_anon = anon_client.get("/keuangan.php")
        anon_access = r_anon.status_code == 200 and r_anon.url.path == "/keuangan.php" and "rekening" in _body(r_anon).lower()
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    # Try as humas: in vuln mode, any logged-in user passes (broken function-level auth)
    # In hardened mode, humas receives HTTP 403 Akses ditolak
    humas_access = False
    try:
        acc = by_role("humas")
        humas_client = _mc(base_url=str(client.base_url).rstrip("/") or BASE_SIMAD)
        lr = _login_simad(humas_client, acc.username, acc.password)
        r_humas = humas_client.get("/keuangan.php")
        humas_access = r_humas.status_code == 200 and r_humas.url.path == "/keuangan.php" and "rekening" in _body(r_humas).lower()
    except Exception:
        humas_access = False

    vuln = anon_access or humas_access
    evidence = f"anon_access={anon_access} humas_access={humas_access} humas_status={getattr(r_humas, 'status_code', 'err')}"
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
    evidence = f"status={r.status_code} is_csv={is_csv} has_pii={has_pii} rows~{rows}"
    leaked = ["no_ktp", "rekening", "npwp", "handphone", "email"] if vuln else []
    return _status_check(vuln, id_, cat, sev, ep, evidence, leaked=leaked, rows=rows)


# ---------------------------------------------------------------------------
# A9 — Sensitive files exposed
# ---------------------------------------------------------------------------
def check_A9(client: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "A9"
    cat = "File sensitif di web root"
    sev: Severity = "critical"
    ep  = "/backup/, /.env"

    found: list[str] = []
    try:
        paths = [
            "/backup/",
            "/backup/simad_backup_2026-10-28.sql",
            "/.env",
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

    # A12 must use a fresh client — the shared client's cookie jar may already
    # hold SIMADSESSID from earlier checks, causing the server to skip Set-Cookie.
    # We need the raw Set-Cookie header to inspect flags.
    from ..client import make_client as _mc
    try:
        tmp_client = _mc(base_url=str(client.base_url).rstrip("/") or BASE_SIMAD)
        acc = by_role("admin")
        r = tmp_client.post("/login.php", data={"username": acc.username, "password": acc.password})
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
    evidence = f"has_simadsessid={has_simadsessid} httponly={not missing_httponly} samesite={not missing_samesite} set-cookie={all_sc[:1]}"
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
    ep  = "/dashboard.php"

    has_audit = False
    warning_present = False
    try:
        from ..client import make_client as _mc
        admin_client = _mc(base_url=str(client.base_url).rstrip("/") or BASE_SIMAD)
        acc = by_role("admin")
        _login_simad(admin_client, acc.username, acc.password)
        r = admin_client.get("/dashboard.php")
        body = _body(r)
        has_audit = "log audit akses data" in body.lower()
        warning_present = "tidak mencatat" in body.lower()
    except Exception as exc:
        return _skip(id_, cat, sev, ep, str(exc))

    # In vuln mode: audit is absent or warns "tidak mencatat siapa mengakses data"
    # In hardened mode: audit log table is active and recording actions
    vuln = warning_present or not has_audit
    evidence = f"dashboard_has_audit_section={has_audit} warning_tidak_mencatat={warning_present}"
    return _status_check(vuln, id_, cat, sev, ep, evidence)


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_A1, check_A2, check_A3, check_A4,
    check_A6, check_A7, check_A8, check_A9, check_A10,
    check_A11, check_A12, check_A13, check_A14, check_A15,
    check_A5,  # Run brute-force test last so IP rate limit does not lock out subsequent checks
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
    # Sort findings by numerical ID (A1..A15) for consistent report presentation
    findings.sort(key=lambda x: int(x.id[1:]) if x.id.startswith("A") and x.id[1:].isdigit() else 99)
    return findings
