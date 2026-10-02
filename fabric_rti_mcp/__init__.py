from fabric_rti_mcp import _tls_compat

# Must run before any TLS connection is established. See _tls_compat for why.
_tls_compat.apply()

try:
    from importlib.metadata import version

    __version__ = version("microsoft-fabric-rti-mcp")
except Exception:
    __version__ = "0.0.0.dev0"
