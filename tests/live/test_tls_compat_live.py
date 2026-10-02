"""Live check that the TLS shim keeps Kusto handshakes working.

Marked ``live`` because it needs network access; excluded from the default
pytest run by ``addopts`` in pyproject.toml. Run it with ``pytest -m live``.

Needs no credentials: the handshake fails before authentication, so
``/v1/rest/auth/metadata`` answers unauthenticated.
"""

from __future__ import annotations

import os
import ssl
import time
import urllib.error
import urllib.request

import pytest

# Importing the package applies the TLS shim as a side effect.
import fabric_rti_mcp  # noqa: F401
from fabric_rti_mcp import _tls_compat

pytestmark = pytest.mark.live

DEFAULT_HOST = "help.kusto.windows.net"
ATTEMPTS = 3
BACKOFF_SECONDS = 5

# OpenSSL started offering X25519MLKEM768 by default in 3.5. Older versions
# never send a post-quantum key share, so they cannot exercise this bug.
MIN_PQ_OPENSSL = (3, 5)

requires_post_quantum_openssl = pytest.mark.skipif(
    ssl.OPENSSL_VERSION_INFO[:2] < MIN_PQ_OPENSSL,
    reason=(
        f"{ssl.OPENSSL_VERSION} predates post-quantum TLS defaults; "
        "use an interpreter bundling its own OpenSSL (uv python-build-standalone)"
    ),
)


def _kusto_host() -> str:
    return os.environ.get("TLS_COMPAT_HOST", DEFAULT_HOST)


def test_shim_is_active() -> None:
    """The shim must have run at import time, before any TLS connection."""
    assert os.environ.get("OPENSSL_CONF")
    assert "X25519MLKEM768" in _tls_compat.PREFERRED_GROUPS
    assert _tls_compat.PREFERRED_GROUPS.split(":")[0] != "X25519MLKEM768"


@requires_post_quantum_openssl
def test_kusto_handshake_succeeds() -> None:
    """A TLS handshake against a Kusto query endpoint must complete.

    Without the shim this fails with SSLEOFError, which azure-kusto-data
    rewraps as a misleading KustoNetworkError about authentication.
    """
    host = _kusto_host()
    url = f"https://{host}/v1/rest/auth/metadata"
    print(f"\nopenssl: {ssl.OPENSSL_VERSION}\ngroups : {_tls_compat.PREFERRED_GROUPS}")

    last_error: Exception | None = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                assert response.status == 200
                return
        except urllib.error.HTTPError:
            # Any HTTP status means the handshake completed, which is all we check.
            return
        except Exception as error:  # noqa: BLE001 - reported via pytest.fail below
            last_error = error
            print(f"attempt {attempt}/{ATTEMPTS}: {type(error).__name__}: {error}")
            if attempt < ATTEMPTS:
                time.sleep(BACKOFF_SECONDS)

    pytest.fail(
        f"TLS handshake to {host} failed with the shim applied "
        f"({type(last_error).__name__}: {last_error}). Either the shim regressed, "
        "or the group ordering no longer avoids the post-quantum key share."
    )
