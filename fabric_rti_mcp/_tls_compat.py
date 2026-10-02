"""Keep post-quantum TLS key shares out of the leading position.

Kusto query endpoints do not respond to a ClientHello carrying an ML-KEM key
share -- no ServerHello, no TLS alert. OpenSSL >= 3.5 offers X25519MLKEM768
first by default, so Python builds linked against it fail with SSLEOFError,
which azure-kusto-data rewraps as a misleading KustoNetworkError.

OpenSSL sends a speculative key share for the leading group only, so demoting
the PQ group is enough; peers that prefer it can still select it via
HelloRetryRequest. secp256r1 leads because Kusto negotiates it anyway.
"""

from __future__ import annotations

import logging
import os
import pathlib
import tempfile

logger = logging.getLogger("fabric-rti-mcp")

PREFERRED_GROUPS = "secp256r1:x25519:X25519MLKEM768:x448:secp521r1:secp384r1"

_OPENSSL_CONF_TEMPLATE = """openssl_conf = fabric_rti_init

[fabric_rti_init]
ssl_conf = fabric_rti_ssl

[fabric_rti_ssl]
system_default = fabric_rti_ssl_defaults

[fabric_rti_ssl_defaults]
Groups = {groups}
"""


def apply() -> None:
    """Point ``OPENSSL_CONF`` at a config that demotes post-quantum TLS groups.

    Idempotent. Never raises: the shim must not block server startup.
    """
    if os.environ.get("OPENSSL_CONF"):
        # An explicit operator setting always wins.
        return

    try:
        config_path = pathlib.Path(tempfile.gettempdir()) / "fabric-rti-mcp-openssl.cnf"
        config_path.write_text(_OPENSSL_CONF_TEMPLATE.format(groups=PREFERRED_GROUPS))
        os.environ["OPENSSL_CONF"] = str(config_path)
    except OSError as exc:
        logger.warning("Could not apply TLS compatibility shim: %s", exc)
