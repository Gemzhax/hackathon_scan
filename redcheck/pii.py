"""redcheck/pii.py — PII pattern library + scoreboard counter.

Counts raw (plaintext) unique PII values exposed in HTTP responses.
Deduplicates per value: the same NIK seen 10 times counts as 1.
Ciphertext (enc:v1 / tok:v1 prefix) → NOT counted as exposed.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# PII classes (per plan contract)
# ---------------------------------------------------------------------------
PII_CLASSES = ("nik", "rekening", "alamat", "email", "hp", "agama", "kesehatan", "npwp")

# ---------------------------------------------------------------------------
# Field-to-class mapping (covers both web_legacy and web_modern field names)
# ---------------------------------------------------------------------------
FIELD_CLASS: dict[str, str] = {
    # nik / no_ktp
    "no_ktp": "nik",
    "nik": "nik",
    # rekening / account_no
    "rekening": "rekening",
    "account_no": "rekening",
    # alamat
    "alamat_jakarta": "alamat",
    "alamat_daerah": "alamat",
    "address_jakarta": "alamat",
    "address_region": "alamat",
    # email
    "email": "email",
    # hp / handphone / phone / mobile
    "handphone": "hp",
    "telpon_jakarta": "hp",
    "telpon_daerah": "hp",
    "phone_jakarta": "hp",
    "phone_region": "hp",
    "mobile": "hp",
    # agama / religion
    "agama": "agama",
    "religion": "agama",
    # kesehatan (health fields)
    "allergy_note": "kesehatan",
    "condition_note": "kesehatan",
    "blood_type": "kesehatan",
    # npwp
    "npwp": "npwp",
}

# ---------------------------------------------------------------------------
# Regex patterns for in-text PII detection
# ---------------------------------------------------------------------------
_PATTERNS: dict[str, re.Pattern[str]] = {
    "nik": re.compile(r"\b\d{16}\b"),
    "rekening": re.compile(r"\b\d{10,18}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "hp": re.compile(r"\b(?:\+62|62|0)[\s\-]?\d{3,4}[\s\-]?\d{3,4}[\s\-]?\d{3,5}\b"),
    "npwp": re.compile(r"\b\d{2}[.\-]\d{3}[.\-]\d{3}[.\-]\d{1}[.\-]\d{3}[.\-]\d{3}\b"),
    "alamat": re.compile(
        r"(?:Jl\.|Jalan|Gang|Gg\.)\s+[^\n\r,]{5,80}", re.IGNORECASE
    ),
    "agama": re.compile(
        r"\b(?:Islam|Kristen|Katolik|Hindu|Buddha|Konghucu|Protestan)\b",
        re.IGNORECASE,
    ),
    "kesehatan": re.compile(
        r"\b(?:Hipertensi|Diabetes|Alergi|Asma|Jantung|Positif|Negatif|A\+|B\+|O\+|AB[+-]?)\b",
        re.IGNORECASE,
    ),
}

_PROTECTED_PREFIX = re.compile(r"^(?:enc:|tok:)")


def _is_ciphertext(value: str) -> bool:
    return bool(_PROTECTED_PREFIX.match(str(value)))


# ---------------------------------------------------------------------------
# Scoreboard accumulator
# ---------------------------------------------------------------------------
@dataclass
class Scoreboard:
    """Dedup-per-value PII counter across all check responses."""

    _seen: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def ingest_value(self, pii_class: str, raw_value: str) -> None:
        """Register one raw string value under a PII class."""
        v = str(raw_value).strip()
        if not v or _is_ciphertext(v):
            return
        self._seen[pii_class].add(v)

    def ingest_field(self, field_name: str, raw_value: str) -> None:
        """Map a field name → PII class then ingest."""
        cls = FIELD_CLASS.get(field_name.lower())
        if cls:
            self.ingest_value(cls, raw_value)

    def scan_text(self, text: str) -> dict[str, list[str]]:
        """Regex-scan *text* for PII patterns, ingest matches, return found map."""
        found: dict[str, list[str]] = {}
        for cls, pat in _PATTERNS.items():
            matches = pat.findall(text)
            if matches:
                found[cls] = matches
                for m in matches:
                    self.ingest_value(cls, m)
        return found

    def scan_json(self, obj: object) -> None:
        """Walk a JSON-decoded object; ingest any recognised field values."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str):
                    self.ingest_field(k, v)
                    # also regex-scan free-text fields
                    if k in ("notes", "alamat_jakarta", "alamat_daerah",
                              "address_jakarta", "address_region"):
                        self.scan_text(v)
                elif isinstance(v, (dict, list)):
                    self.scan_json(v)
        elif isinstance(obj, list):
            for item in obj:
                self.scan_json(item)

    def totals(self) -> dict[str, int]:
        return {cls: len(self._seen.get(cls, set())) for cls in PII_CLASSES}

    def merge(self, other: "Scoreboard") -> None:
        for cls, vals in other._seen.items():
            self._seen[cls].update(vals)
