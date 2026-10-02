"""Compatibility shim for Kusto endpoints that reject post-quantum TLS key shares.

OpenSSL 3.5 enabled the hybrid ``X25519MLKEM768`` group by default and offers it
first. Python builds linked against OpenSSL >= 3.5 (notably CPython 3.12+ from
python-build-standalone, which ``uv`` installs) therefore send a ~1.4 KB
ClientHello carrying an ML-KEM key share.

Azure Data Explorer query endpoints do not answer that ClientHello. They send
neither a ServerHello nor a TLS alert -- ``openssl s_client`` reports
"read 0 bytes and written 1446 bytes" -- so the handshake dies with::

    ssl.SSLEOFError: [SSL: UNEXPECTED_EOF_WHILE_READING]

azure-kusto-data wraps that in ``KustoNetworkError``, which surfaces as::

    Failed to process network request for the endpoint:
    https://<cluster>/v1/rest/auth/metadata

That message reads like an authentication or connectivity problem, which has
repeatedly sent users down the wrong debugging path. ``curl`` is unaffected on
macOS because it links LibreSSL, making the failure look client-specific.

Restricting the offered groups to classical curves keeps the ClientHello small
and the handshake succeeds. ``secp256r1`` is listed first because it is what
these endpoints negotiate anyway, which also avoids a HelloRetryRequest round
trip.

Set ``OPENSSL_CONF`` yourself to opt out; an existing value is never overridden.
"""

from __future__ import annotations

import logging
import os
import pathlib
import tempfile

logger = logging.getLogger("fabric-rti-mcp")

CLASSICAL_GROUPS = "secp256r1:x25519:x448:secp521r1:secp384r1"

_OPENSSL_CONF_TEMPLATE = """openssl_conf = fabric_rti_init

[fabric_rti_init]
ssl_conf = fabric_rti_ssl

[fabric_rti_ssl]
system_default = fabric_rti_ssl_defaults

[fabric_rti_ssl_defaults]
Groups = {groups}
"""


def apply() -> None:
    """Point ``OPENSSL_CONF`` at a config restricting TLS groups to classical curves.

    Safe to call more than once. Never raises: a failure here must not stop the
    server from starting, since the shim is only needed on some platforms.
    """
    if os.environ.get("OPENSSL_CONF"):
        # An explicit operator setting always wins.
        return

    try:
        config_path = pathlib.Path(tempfile.gettempdir()) / "fabric-rti-mcp-openssl.cnf"
        config_path.write_text(_OPENSSL_CONF_TEMPLATE.format(groups=CLASSICAL_GROUPS))
        os.environ["OPENSSL_CONF"] = str(config_path)
    except OSError as exc:
        logger.warning("Could not apply TLS compatibility shim: %s", exc)
