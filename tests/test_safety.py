"""tests/test_safety.py — assert allowlist enforcement."""
import pytest
from redcheck.safety import assert_allowed, ALLOW_HOSTS, ALLOW_PORTS


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/",
    "http://localhost:3000/api/members",
    "http://127.0.0.1:3000/",
    "http://web-legacy:8080/login.php",
    "http://web-modern:3000/api/config",
    "http://127.0.0.1:8443/",
    "http://127.0.0.1:8444/",
])
def test_allowed(url):
    assert_allowed(url)  # must not raise


@pytest.mark.parametrize("url", [
    "http://evil.com:8080/",
    "http://10.0.0.1:8080/",
    "http://127.0.0.1:9999/",
    "http://127.0.0.1:80/",
    "http://192.168.1.1:3000/",
    "https://attacker.example.com/",
    "http://localhost:22/",
])
def test_refused(url):
    with pytest.raises(SystemExit) as exc_info:
        assert_allowed(url)
    assert exc_info.value.code == 2
