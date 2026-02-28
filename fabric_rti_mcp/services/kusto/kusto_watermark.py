from __future__ import annotations

import json
import os
import re

from fabric_rti_mcp import __version__  # type: ignore
from fabric_rti_mcp.config import logger


def _sanitize_value(value: str) -> str:
    """Remove newlines and carriage returns from a watermark value to prevent query injection."""
    return re.sub(r"[\r\n]+", " ", value).strip()


def _resolve_custom_watermark(custom_watermark_json: str) -> dict[str, str]:
    """Resolve custom watermark entries from a JSON mapping of keys to environment variable names.

    :param custom_watermark_json: JSON string mapping custom keys to env var names,
        e.g. '{"team": "TEAM_NAME", "request_id": "REQUEST_ID"}'.
    :return: Resolved dict mapping custom keys to the env var values.
    """
    try:
        mapping = json.loads(custom_watermark_json)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse custom watermark JSON: {e}. Skipping custom watermark.")
        return {}

    if not isinstance(mapping, dict):
        logger.error("Custom watermark must be a JSON object mapping keys to environment variable names.")
        return {}

    resolved: dict[str, str] = {}
    for key, env_var_name in mapping.items():
        if not isinstance(env_var_name, str):
            logger.warning(f"Custom watermark value for '{key}' is not a string, skipping.")
            continue
        env_value = os.getenv(env_var_name, "")
        if env_value:
            resolved[key] = _sanitize_value(env_value)
    return resolved


CUSTOM_WATERMARK_ENV_VAR = "FABRIC_RTI_KUSTO_CUSTOM_WATERMARK"


def build_watermark() -> str:
    """Build a KQL comment watermark to prepend to queries.

    The watermark is a single-line KQL comment containing a JSON object with:
    - ``fabric_rti_mcp_version``: the current package version
    - ``user``: the OS-level username (best effort)
    - any custom key-value pairs resolved from the ``FABRIC_RTI_KUSTO_CUSTOM_WATERMARK`` env var

    :return: A KQL comment string ending with a newline, e.g.
        ``// {"fabric_rti_mcp_version": "0.1.0", "user": "alice"}\\n``
    """
    watermark_data: dict[str, str] = {
        "fabric_rti_mcp_version": __version__,
    }

    # Best-effort user detection
    user = os.getenv("USER") or os.getenv("USERNAME") or ""
    if user:
        watermark_data["user"] = _sanitize_value(user)

    # Resolve custom watermark entries
    custom_watermark_json = os.getenv(CUSTOM_WATERMARK_ENV_VAR)
    if custom_watermark_json:
        custom_entries = _resolve_custom_watermark(custom_watermark_json)
        watermark_data.update(sorted(custom_entries.items()))

    return f"// {json.dumps(watermark_data)}\n"


def add_watermark(query: str) -> str:
    """Prepend a watermark comment to a KQL query."""
    return build_watermark() + query
