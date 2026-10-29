"""redcheck/report.py — scoreboard aggregation + standalone HTML compare generator."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .schema import Report, Finding, load_report
from .pii import PII_CLASSES


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def count_by_status(findings: list[Finding]) -> dict[str, int]:
    c = {"pass": 0, "fail": 0, "skip": 0}
    for f in findings:
        c[f.status] = c.get(f.status, 0) + 1
    return c


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    c: dict[str, int] = {}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


# ---------------------------------------------------------------------------
# HTML generator
# ---------------------------------------------------------------------------

_SEVERITY_COLOR = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#27ae60",
    "info":     "#2980b9",
}

_STATUS_EMOJI = {"pass": "✅", "fail": "❌", "skip": "⚠️"}


def _esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


def build_compare_html(
    vuln: Report,
    hardened: Report,
    out_path: Path,
) -> None:
    """Generate a standalone compare HTML from two Report objects."""

    pii_rows = _pii_table_rows(vuln.scoreboard, hardened.scoreboard)
    finding_rows = _finding_rows(vuln.findings, hardened.findings)
    summary_vuln   = count_by_status(vuln.findings)
    summary_hard   = count_by_status(hardened.findings)
    sev_vuln   = count_by_severity(vuln.findings)
    sev_hard   = count_by_severity(hardened.findings)

    html = _HTML_TEMPLATE.format(
        vuln_mode=_esc(vuln.mode),
        hard_mode=_esc(hardened.mode),
        generated_at=_esc(vuln.generated_at),
        pii_rows=pii_rows,
        finding_rows=finding_rows,
        vuln_pass=summary_vuln["pass"],
        vuln_fail=summary_vuln["fail"],
        vuln_skip=summary_vuln.get("skip", 0),
        hard_pass=summary_hard["pass"],
        hard_fail=summary_hard["fail"],
        hard_skip=summary_hard.get("skip", 0),
        sev_rows=_sev_rows(sev_vuln, sev_hard),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    print(f"[RedCheck] compare.html written -> {out_path}")


def _pii_table_rows(vuln_sb: dict, hard_sb: dict) -> str:
    rows = []
    for cls in PII_CLASSES:
        v = vuln_sb.get(cls, 0)
        h = hard_sb.get(cls, 0)
        delta = h - v
        delta_str = f"{delta:+d}" if delta != 0 else "—"
        color = "#27ae60" if delta < 0 else ("#c0392b" if delta > 0 else "#888")
        rows.append(
            f"<tr><td>{_esc(cls)}</td><td class='num'>{v}</td>"
            f"<td class='num'>{h}</td>"
            f"<td class='num' style='color:{color}'>{delta_str}</td></tr>"
        )
    return "\n".join(rows)


def _sev_rows(sv: dict, sh: dict) -> str:
    rows = []
    for sev in ("critical", "high", "medium", "low", "info"):
        color = _SEVERITY_COLOR.get(sev, "#888")
        rows.append(
            f"<tr><td style='color:{color}'><b>{sev}</b></td>"
            f"<td class='num'>{sv.get(sev,0)}</td>"
            f"<td class='num'>{sh.get(sev,0)}</td></tr>"
        )
    return "\n".join(rows)


def _finding_rows(vuln_fs: list[Finding], hard_fs: list[Finding]) -> str:
    # Map by ID
    vmap = {f.id: f for f in vuln_fs}
    hmap = {f.id: f for f in hard_fs}
    all_ids = sorted(set(vmap) | set(hmap))
    rows = []
    for fid in all_ids:
        vf = vmap.get(fid)
        hf = hmap.get(fid)
        category = (vf or hf).category  # type: ignore[union-attr]
        sev = (vf or hf).severity       # type: ignore[union-attr]
        sev_color = _SEVERITY_COLOR.get(sev, "#888")
        vs = _STATUS_EMOJI.get(vf.status, "?") if vf else "—"
        hs = _STATUS_EMOJI.get(hf.status, "?") if hf else "—"
        ep = _esc((vf or hf).endpoint)  # type: ignore[union-attr]
        note_v = _esc((vf.evidence_snippet or "")[:120]) if vf else ""
        note_h = _esc((hf.evidence_snippet or "")[:120]) if hf else ""
        rows.append(
            f"<tr>"
            f"<td><code>{_esc(fid)}</code></td>"
            f"<td>{_esc(category)}</td>"
            f"<td style='color:{sev_color}'>{sev}</td>"
            f"<td>{_esc(ep)}</td>"
            f"<td class='center'>{vs}</td>"
            f"<td class='center'>{hs}</td>"
            f"<td class='snip'>{note_v}</td>"
            f"<td class='snip'>{note_h}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Triguna RedCheck — Before/After Report</title>
<style>
:root{{
  --bg:#0f1117;--card:#1a1d2b;--border:#2a2d40;--text:#e0e0e8;
  --green:#27ae60;--red:#c0392b;--yellow:#f1c40f;--blue:#2980b9;
  --font:'Segoe UI',system-ui,sans-serif;
}}
@media(prefers-color-scheme:light){{
  :root{{--bg:#f5f6fa;--card:#fff;--border:#dde;--text:#1a1a2e;}}
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:var(--font);padding:2rem;}}
h1{{font-size:1.6rem;margin-bottom:.25rem;}}
h2{{font-size:1.1rem;margin:1.5rem 0 .5rem;border-bottom:1px solid var(--border);padding-bottom:.3rem;}}
.meta{{font-size:.8rem;opacity:.6;margin-bottom:1.5rem;}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem 1.25rem;margin-bottom:1.5rem;overflow-x:auto;}}
table{{width:100%;border-collapse:collapse;font-size:.85rem;}}
th,td{{padding:.45rem .6rem;border-bottom:1px solid var(--border);text-align:left;}}
th{{opacity:.75;font-weight:600;}}
td.num{{text-align:right;font-variant-numeric:tabular-nums;}}
td.center{{text-align:center;}}
td.snip{{font-size:.75rem;max-width:220px;word-break:break-all;opacity:.8;}}
.summary-grid{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem;}}
.chip{{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:.5rem .85rem;font-size:.82rem;}}
.chip b{{display:block;font-size:1.3rem;}}
.pass{{color:var(--green);}}.fail{{color:var(--red);}}.skip{{color:var(--yellow);}}
code{{background:rgba(128,128,200,.15);padding:.1em .3em;border-radius:3px;font-size:.85em;}}
</style>
</head>
<body>
<h1>🛡️ Triguna RedCheck — Before / After</h1>
<p class="meta">Generated: {generated_at} &nbsp;|&nbsp; vuln mode: <b>{vuln_mode}</b> &nbsp;→&nbsp; hardened mode: <b>{hard_mode}</b></p>

<h2>📊 Summary</h2>
<div class="summary-grid">
  <div class="chip"><b class="fail">{vuln_fail}</b>Fail (vuln)</div>
  <div class="chip"><b class="pass">{vuln_pass}</b>Pass (vuln)</div>
  <div class="chip"><b class="fail">{hard_fail}</b>Fail (hardened)</div>
  <div class="chip"><b class="pass">{hard_pass}</b>Pass (hardened)</div>
  <div class="chip"><b class="skip">{vuln_skip}</b>Skip (vuln)</div>
</div>

<h2>🔴 PII Leak Scoreboard</h2>
<div class="card">
<table>
<thead><tr><th>PII Class</th><th>Vuln (unique values)</th><th>Hardened</th><th>Δ</th></tr></thead>
<tbody>
{pii_rows}
</tbody>
</table>
</div>

<h2>⚠️ Severity Distribution</h2>
<div class="card">
<table>
<thead><tr><th>Severity</th><th>Vuln count</th><th>Hardened count</th></tr></thead>
<tbody>
{sev_rows}
</tbody>
</table>
</div>

<h2>🔍 Finding Detail</h2>
<div class="card">
<table>
<thead><tr>
  <th>ID</th><th>Category</th><th>Sev</th><th>Endpoint</th>
  <th>Vuln</th><th>Hard</th>
  <th>Evidence (vuln)</th><th>Evidence (hard)</th>
</tr></thead>
<tbody>
{finding_rows}
</tbody>
</table>
</div>

<p class="meta" style="margin-top:2rem">Triguna RedCheck v1.0 · Hackathon DPR RI 2026</p>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI entry (used by make compare)
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse, sys
    ap = argparse.ArgumentParser(description="Generate compare.html")
    ap.add_argument("--vuln",     required=True)
    ap.add_argument("--hardened", required=True)
    ap.add_argument("--out",      default="out/compare.html")
    args = ap.parse_args()

    vp = Path(args.vuln)
    hp = Path(args.hardened)
    if not vp.exists():
        print(f"[RedCheck] missing {vp}", file=__import__("sys").stderr)
        sys.exit(1)
    if not hp.exists():
        print(f"[RedCheck] missing {hp}", file=__import__("sys").stderr)
        sys.exit(1)

    build_compare_html(load_report(vp), load_report(hp), Path(args.out))


if __name__ == "__main__":
    main()
