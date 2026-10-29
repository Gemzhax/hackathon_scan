"""redcheck/schema.py — Finding & Report dataclasses + JSON writer."""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal


Status   = Literal["pass", "fail", "skip"]
Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    id: str                          # e.g. "A1", "B7"
    category: str                    # human label
    severity: Severity
    endpoint: str                    # URL or path tested
    status: Status                   # pass | fail | skip
    leaked_fields: list[str] = field(default_factory=list)
    rows_exposed: int = 0
    evidence_snippet: str = ""       # ≤200 chars of evidence
    note: str = ""                   # optional human note / [PLANNED] tag


@dataclass
class Report:
    target: str           # "simad" | "parlemen360" | "combined"
    mode: str             # "vuln" | "hardened" | "unknown"
    generated_at: str     # ISO-8601
    findings: list[Finding] = field(default_factory=list)
    scoreboard: dict[str, int] = field(default_factory=dict)

    # -----------------------------------------------------------------------

    @classmethod
    def empty(cls, target: str, mode: str) -> "Report":
        return cls(
            target=target,
            mode=mode,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[RedCheck] wrote {path}")


def load_report(path: Path) -> Report:
    raw = json.loads(path.read_text(encoding="utf-8"))
    findings = [Finding(**f) for f in raw.get("findings", [])]
    return Report(
        target=raw["target"],
        mode=raw["mode"],
        generated_at=raw["generated_at"],
        findings=findings,
        scoreboard=raw.get("scoreboard", {}),
    )
