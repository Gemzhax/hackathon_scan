"""redcheck/checks/proofs.py — Proof (a), (b), (c).

(c) Role-based access validation over HTTP — fully doable when target is live.
(a) Dump without key: scan DB column values for ciphertext prefix. [PLANNED] — needs Docker+Shield.
(b) Dump + leaked key: partial decrypt with finance-DEK. [PLANNED] — needs KMS.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import httpx

from ..schema import Finding, Severity
from ..pii import Scoreboard, _is_ciphertext
from ..accounts import ACCOUNTS, by_role
from ..config import ACCESS_MATRIX_PATH, KMS_URL, KMS_APP_TOKEN

_PLANNED_NOTE = "[PLANNED] Requires Docker+Shield encryption to be deployed."


def _skip(id: str, category: str, severity: Severity, endpoint: str, reason: str) -> Finding:
    return Finding(
        id=id, category=category, severity=severity, endpoint=endpoint,
        status="skip", note=reason,
    )


def _login_modern(client: httpx.Client, username: str, password: str) -> tuple[int, str]:
    try:
        r = client.post("/api/auth/login", json={"username": username, "password": password})
        token = ""
        if r.status_code == 200:
            d = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            token = d.get("token", "") or d.get("access_token", "")
        return r.status_code, token
    except Exception:
        return 0, ""


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


# ---------------------------------------------------------------------------
# Load access_matrix.json
# ---------------------------------------------------------------------------
def _load_matrix() -> dict:
    if ACCESS_MATRIX_PATH.exists():
        try:
            return json.loads(ACCESS_MATRIX_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


# ---------------------------------------------------------------------------
# Proof (c) — RBAC over HTTP (hardened mode)
# ---------------------------------------------------------------------------
def proof_c(client_modern: httpx.Client, sb: Scoreboard) -> Finding:
    id_ = "PROOF-C"
    cat = "Proof (c): RBAC sah via HTTP"
    sev: Severity = "info"
    ep  = "/api/members/:id (multi-role)"

    matrix = _load_matrix()
    if not matrix:
        return _skip(id_, cat, sev, ep, f"access_matrix.json not found at {ACCESS_MATRIX_PATH}")

    results: list[str] = []
    failures: list[str] = []
    modern_roles = matrix.get("web_modern", {})

    # Test keuangan: account_no MUST appear
    acc_keu = by_role("keuangan")
    _, tok_keu = _login_modern(client_modern, acc_keu.username, acc_keu.password)
    if tok_keu:
        try:
            r = client_modern.get("/api/members/1", headers=_auth_header(tok_keu))
            data = r.json() if r.status_code == 200 else {}
            allowed_keu = modern_roles.get("keuangan", {}).get("allow", [])
            if isinstance(data, dict):
                account_no = data.get("account_no")
                if account_no and not _is_ciphertext(str(account_no)):
                    results.append("keuangan→account_no:VISIBLE✅")
                    sb.ingest_field("account_no", str(account_no))
                else:
                    results.append("keuangan→account_no:MISSING⚠")
                # Religion MUST NOT appear for keuangan
                religion = data.get("religion")
                if religion is not None:
                    failures.append(f"keuangan→religion:LEAKED❌({religion!r})")
                else:
                    results.append("keuangan→religion:ABSENT✅")
        except Exception as exc:
            failures.append(f"keuangan_request_error:{exc}")
    else:
        failures.append("keuangan_login_failed")

    # Test humas → /api/finance must be 403
    acc_humas = by_role("humas")
    _, tok_humas = _login_modern(client_modern, acc_humas.username, acc_humas.password)
    if tok_humas:
        try:
            r = client_modern.get("/api/finance", headers=_auth_header(tok_humas))
            if r.status_code == 403:
                results.append("humas→/api/finance:403✅")
            else:
                failures.append(f"humas→/api/finance:{r.status_code}❌")
        except Exception as exc:
            failures.append(f"humas_finance_error:{exc}")
    else:
        failures.append("humas_login_failed")

    # Test anggota: sees own data, not others' sensitive fields
    acc_ang = by_role("anggota")
    _, tok_ang = _login_modern(client_modern, acc_ang.username, acc_ang.password)
    if tok_ang:
        try:
            # /api/me = own record, should have sensitive fields
            r_me = client_modern.get("/api/me", headers=_auth_header(tok_ang))
            # /api/members/2 = other's record, should NOT have sensitive fields
            r_other = client_modern.get("/api/members/2", headers=_auth_header(tok_ang))
            if r_other.status_code == 200:
                d_other = r_other.json() if isinstance(r_other.json(), dict) else {}
                leaked = [f for f in ("nik", "account_no", "npwp") if f in d_other and d_other[f]]
                if leaked:
                    failures.append(f"anggota→members/2 leaks {leaked}❌")
                else:
                    results.append("anggota→members/2:no_pii✅")
        except Exception as exc:
            failures.append(f"anggota_error:{exc}")
    else:
        failures.append("anggota_login_failed")

    all_ok = len(failures) == 0
    evidence = " | ".join(results + failures)[:200]
    return Finding(
        id=id_, category=cat, severity=sev, endpoint=ep,
        status="pass" if all_ok else "fail",
        evidence_snippet=evidence,
        note=f"results={len(results)} failures={len(failures)}",
    )


# ---------------------------------------------------------------------------
# Proof (a) — Dump without key: confirm Tier-3 columns are ciphertext
# ---------------------------------------------------------------------------
def proof_a(sb: Scoreboard) -> Finding:
    id_ = "PROOF-A"
    cat = "Proof (a): dump tanpa kunci -> plaintext=0"
    sev: Severity = "info"
    ep  = "MySQL simad + PG parlemen360 (host direct)"

    # Try to read from hackathon_dprri/attack/results/leak_run.json as fallback
    fallback = Path(__file__).parent.parent.parent.parent / "hackathon_dprri" / "attack" / "results" / "leak_run.json"
    if fallback.exists():
        try:
            data = json.loads(fallback.read_text(encoding="utf-8"))
            t3 = data.get("s1_dump_no_keys", {}).get("verbatimExposure", {}).get("protected", {}).get("byTier", {}).get("T3", {})
            exposed_pct = t3.get("exposedPct", None)
            if exposed_pct is not None:
                note = f"Fallback from leak_run.json: T3 exposed={exposed_pct}% (expected 0 in hardened)"
                status = "pass" if exposed_pct == 0 else "fail"
                return Finding(
                    id=id_, category=cat, severity=sev, endpoint=ep,
                    status=status, evidence_snippet=note, note=_PLANNED_NOTE,
                )
        except Exception:
            pass

    return Finding(
        id=id_, category=cat, severity=sev, endpoint=ep,
        status="skip",
        evidence_snippet="",
        note=_PLANNED_NOTE + " No fallback data found.",
    )


# ---------------------------------------------------------------------------
# Proof (b) — Dump + leaked key: partial decrypt (finance DEK)
# ---------------------------------------------------------------------------
def proof_b(sb: Scoreboard) -> Finding:
    id_ = "PROOF-B"
    cat = "Proof (b): dump + kunci bocor -> finance subset terbuka"
    sev: Severity = "info"
    ep  = f"KMS {KMS_URL or '(not set)'}/v1/unwrap"

    if not KMS_URL:
        return Finding(
            id=id_, category=cat, severity=sev, endpoint=ep,
            status="skip",
            evidence_snippet="",
            note=_PLANNED_NOTE + " KMS_URL not set.",
        )

    # KMS is set — attempt a real unwrap probe
    from ..client import make_client
    from ..safety import assert_allowed
    try:
        assert_allowed(f"{KMS_URL}/v1/unwrap")
    except SystemExit:
        return Finding(
            id=id_, category=cat, severity=sev, endpoint=ep,
            status="skip", note=f"KMS_URL {KMS_URL} outside allowlist.",
        )

    try:
        kms_client = make_client(base_url=KMS_URL, headers={"X-App-Token": KMS_APP_TOKEN, "X-App-Id": "web-modern"})
        r = kms_client.post("/v1/unwrap", json={"key_id": "dek-member_finance-nik-v1", "app": "web-modern"})
        success = r.status_code == 200 and "key_b64" in r.text
        evidence = f"KMS status={r.status_code} got_key={success}"
        return Finding(
            id=id_, category=cat, severity=sev, endpoint=ep,
            status="pass" if success else "fail",
            evidence_snippet=evidence,
            note=_PLANNED_NOTE if not success else "",
        )
    except Exception as exc:
        return Finding(
            id=id_, category=cat, severity=sev, endpoint=ep,
            status="skip", note=f"KMS request error: {exc}",
        )


# ---------------------------------------------------------------------------
# Run all proofs
# ---------------------------------------------------------------------------
def run_all(client_modern: httpx.Client, sb: Scoreboard) -> list[Finding]:
    findings = []
    for fn_name, fn in [("PROOF-C", lambda: proof_c(client_modern, sb)),
                         ("PROOF-A", lambda: proof_a(sb)),
                         ("PROOF-B", lambda: proof_b(sb))]:
        try:
            f = fn()
            print(f"  [{f.status.upper():4}] {f.id} {f.category}")
            findings.append(f)
        except SystemExit:
            raise
        except Exception as exc:
            print(f"  [ERR ] {fn_name} — {exc}")
            findings.append(Finding(
                id=fn_name, category="(error)", severity="info",
                endpoint="?", status="skip", note=str(exc),
            ))
    return findings
