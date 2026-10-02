import importlib
import os
import pathlib

import pytest

from fabric_rti_mcp import _tls_compat


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENSSL_CONF", raising=False)


def test_apply_sets_openssl_conf(clean_env: None) -> None:
    _tls_compat.apply()

    config_path = os.environ.get("OPENSSL_CONF")
    assert config_path is not None
    assert pathlib.Path(config_path).is_file()


def test_config_demotes_but_keeps_post_quantum_groups(clean_env: None) -> None:
    _tls_compat.apply()

    contents = pathlib.Path(os.environ["OPENSSL_CONF"]).read_text()
    # The PQ group is retained so peers can still select it via HelloRetryRequest.
    assert "X25519MLKEM768" in contents
    assert f"Groups = {_tls_compat.PREFERRED_GROUPS}" in contents


def test_post_quantum_group_is_never_first() -> None:
    # OpenSSL sends a speculative key share for the leading group only. Kusto
    # endpoints drop a ClientHello carrying an ML-KEM key share, so the PQ group
    # must not lead.
    groups = _tls_compat.PREFERRED_GROUPS.split(":")
    assert "X25519MLKEM768" in groups
    assert groups[0] != "X25519MLKEM768"


def test_classical_group_list_prefers_secp256r1() -> None:
    # Kusto endpoints negotiate secp256r1; leading with it avoids a
    # HelloRetryRequest round trip.
    assert _tls_compat.PREFERRED_GROUPS.split(":")[0] == "secp256r1"


def test_existing_openssl_conf_is_not_overridden(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENSSL_CONF", "/custom/openssl.cnf")

    _tls_compat.apply()

    assert os.environ["OPENSSL_CONF"] == "/custom/openssl.cnf"


def test_apply_is_idempotent(clean_env: None) -> None:
    _tls_compat.apply()
    first = os.environ["OPENSSL_CONF"]

    _tls_compat.apply()

    assert os.environ["OPENSSL_CONF"] == first


def test_apply_survives_unwritable_tempdir(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(*_args: object, **_kwargs: object) -> None:
        raise OSError("read-only file system")

    monkeypatch.setattr(pathlib.Path, "write_text", _raise)

    # Must not raise: a failed shim should never block server startup.
    _tls_compat.apply()

    assert "OPENSSL_CONF" not in os.environ


def test_package_import_applies_shim(clean_env: None) -> None:
    import fabric_rti_mcp

    importlib.reload(fabric_rti_mcp)

    assert "OPENSSL_CONF" in os.environ
