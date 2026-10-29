"""redcheck/accounts.py — demo accounts from TARGETS.md."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Account:
    role: str
    username: str
    password: str
    note: str = ""


ACCOUNTS: list[Account] = [
    Account("admin",    "admin",    "admin123"),
    Account("humas",    "humas",    "humas123"),
    Account("keuangan", "keuangan", "keuangan123"),
    Account("sdm",      "sdm",      "sdm123"),
    Account("medis",    "medis",    "medis123", note="Parlemen360 only"),
    Account("anggota",  "dummy__,_is..a.,ramm_wh.s.mnso1",    "anggota123", note="anggota #1"),
    Account("anggota",  "dummy_.eunsd.ha._s,.mpa._ru._l_da.m_,2", "anggota123", note="anggota #2"),
]


def by_role(role: str) -> Account:
    for a in ACCOUNTS:
        if a.role == role:
            return a
    raise KeyError(f"No account for role '{role}'")


def all_roles() -> list[str]:
    seen: list[str] = []
    for a in ACCOUNTS:
        if a.role not in seen:
            seen.append(a.role)
    return seen
