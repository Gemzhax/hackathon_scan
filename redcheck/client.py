"""redcheck/client.py — httpx factory with safety guard + deterministic rate limiter."""
from __future__ import annotations

import time
import threading
from typing import Any

import httpx

from .safety import assert_allowed
from .config import RATE_PER_SEC

_INTERVAL: float = 1.0 / max(RATE_PER_SEC, 0.1)
_lock = threading.Lock()
_last_request_time: float = 0.0


def _rate_wait() -> None:
    """Block until rate-limit interval has elapsed since last call."""
    global _last_request_time
    with _lock:
        now = time.monotonic()
        wait = _INTERVAL - (now - _last_request_time)
        if wait > 0:
            time.sleep(wait)
        _last_request_time = time.monotonic()


def _checked_send(
    client: httpx.Client,
    request: httpx.Request,
    **kwargs: Any,
) -> httpx.Response:
    assert_allowed(str(request.url))
    _rate_wait()
    return client.send(request, **kwargs)


def make_client(
    *,
    base_url: str = "",
    timeout: float = 10.0,
    verify: bool = False,
    headers: dict[str, str] | None = None,
) -> httpx.Client:
    """Return an httpx.Client whose every request passes the safety guard."""
    # Patch transport so the guard fires on send()
    transport = _GuardedTransport(verify=verify)
    return httpx.Client(
        base_url=base_url,
        timeout=timeout,
        headers=headers or {},
        transport=transport,
        follow_redirects=True,
    )


class _GuardedTransport(httpx.HTTPTransport):
    """HTTPTransport subclass that enforces safety allowlist + rate limit."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:  # type: ignore[override]
        assert_allowed(str(request.url))
        _rate_wait()
        return super().handle_request(request)
