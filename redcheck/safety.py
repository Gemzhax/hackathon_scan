"""redcheck/safety.py — enforced allowlist for all outbound requests.

Only hosts in ALLOW_HOSTS and ports in ALLOW_PORTS are permitted.
Any URL outside this set calls refuse(), which prints a reason and
raises SystemExit(2) — intentional hard stop.
"""
from __future__ import annotations

import sys
from urllib.parse import urlparse

ALLOW_HOSTS: frozenset[str] = frozenset(
    {"localhost", "127.0.0.1", "web-legacy", "web-modern"}
)
ALLOW_PORTS: frozenset[int] = frozenset({8080, 3000, 8443, 8444})

# Default ports implied when no explicit port in URL
_SCHEME_DEFAULT: dict[str, int] = {"http": 80, "https": 443}


def assert_allowed(url: str) -> None:
    """Parse *url* and verify host+port are in the allowlist.

    Raises SystemExit(2) on any violation — no exception to catch.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or _SCHEME_DEFAULT.get(parsed.scheme, 0)

    host_ok = host.lower() in ALLOW_HOSTS
    port_ok = port in ALLOW_PORTS

    if not host_ok or not port_ok:
        reason = []
        if not host_ok:
            reason.append(f"host '{host}' not in allowlist {sorted(ALLOW_HOSTS)}")
        if not port_ok:
            reason.append(f"port {port} not in allowlist {sorted(ALLOW_PORTS)}")
        print(
            f"[RedCheck] REFUSED {url} — {'; '.join(reason)}",
            file=sys.stderr,
        )
        raise SystemExit(2)
