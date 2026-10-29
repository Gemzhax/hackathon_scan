"""redcheck/runner.py — orchestration entrypoint.

Usage:
  python -m redcheck.runner [--mode vuln|hardened] [--base <url>]

--base overrides both targets for quick safety test.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure stdout/stderr can handle non-ASCII on Windows (cp1252 console)
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf_8"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf_8"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

import httpx

from .config import BASE_SIMAD, BASE_MODERN, OUT_DIR
from .client import make_client
from .safety import assert_allowed
from .pii import Scoreboard
from .schema import Report, Finding
from .checks import legacy_simad, modern_p360, proofs


# ---------------------------------------------------------------------------
# Mode detection helpers
# ---------------------------------------------------------------------------

def _detect_mode_modern(client: httpx.Client) -> str:
    try:
        r = client.get("/api/config")
        if r.status_code == 200:
            data = r.json()
            return data.get("mode", "unknown")
    except Exception:
        pass
    return "unknown"


def _detect_mode_legacy(client: httpx.Client) -> str:
    try:
        r = client.get("/")
        m = re.search(r'<body[^>]*class="([^"]*mode-(vuln|hardened)[^"]*)"', r.text)
        if m:
            return m.group(2)
    except Exception:
        pass
    return "unknown"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Triguna RedCheck runner")
    ap.add_argument("--mode", choices=["vuln", "hardened"], default=None,
                    help="Expected mode (label only; actual mode read from target)")
    ap.add_argument("--base", default=None,
                    help="Override base URL for both targets (safety test)")
    args = ap.parse_args(argv)

    if args.base:
        # Safety test: assert_allowed will SystemExit(2) if outside allowlist
        assert_allowed(args.base + "/")
        print(f"[RedCheck] base URL accepted: {args.base}")
        return 0

    label = args.mode or "run"

    # -----------------------------------------------------------------------
    # SIMAD
    # -----------------------------------------------------------------------
    print(f"\n[RedCheck] === SIMAD ({BASE_SIMAD}) ===")
    client_simad  = make_client(base_url=BASE_SIMAD)
    sb_simad      = Scoreboard()
    mode_simad    = _detect_mode_legacy(client_simad)
    print(f"[RedCheck] detected mode: {mode_simad}")

    simad_findings = legacy_simad.run_all(client_simad, sb_simad)

    simad_report = Report(
        target="simad",
        mode=mode_simad,
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=simad_findings,
        scoreboard=sb_simad.totals(),
    )

    # -----------------------------------------------------------------------
    # Parlemen360
    # -----------------------------------------------------------------------
    print(f"\n[RedCheck] === Parlemen360 ({BASE_MODERN}) ===")
    client_modern = make_client(base_url=BASE_MODERN)
    sb_modern     = Scoreboard()
    mode_modern   = _detect_mode_modern(client_modern)
    print(f"[RedCheck] detected mode: {mode_modern}")

    modern_findings = modern_p360.run_all(client_modern, sb_modern)

    # -----------------------------------------------------------------------
    # Proofs
    # -----------------------------------------------------------------------
    print(f"\n[RedCheck] === Proofs ===")
    proof_findings = proofs.run_all(client_modern, sb_modern)

    # -----------------------------------------------------------------------
    # Combine into single report
    # -----------------------------------------------------------------------
    combined_mode = mode_modern if mode_modern != "unknown" else mode_simad
    if label and combined_mode != "unknown" and combined_mode != label:
        print(f"[RedCheck] WARNING: expected mode '{label}' but target reports '{combined_mode}'",
              file=sys.stderr)

    sb_combined = Scoreboard()
    sb_combined.merge(sb_simad)
    sb_combined.merge(sb_modern)

    combined = Report(
        target="combined",
        mode=combined_mode,
        generated_at=datetime.now(timezone.utc).isoformat(),
        findings=simad_findings + modern_findings + proof_findings,
        scoreboard=sb_combined.totals(),
    )

    out_file = OUT_DIR / f"redcheck_{label}.json"
    combined.write(out_file)

    # Summary
    total = len(combined.findings)
    fail  = sum(1 for f in combined.findings if f.status == "fail")
    ok    = sum(1 for f in combined.findings if f.status == "pass")
    skip  = sum(1 for f in combined.findings if f.status == "skip")
    print(f"\n[RedCheck] DONE — total={total} fail={fail} pass={ok} skip={skip}")
    print(f"[RedCheck] Scoreboard: {combined.scoreboard}")

    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
