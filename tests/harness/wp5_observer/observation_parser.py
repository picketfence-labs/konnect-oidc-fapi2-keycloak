"""Strict parser for the test-only AS peer observer's fixed log rows."""

from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime


MARKER = "WP5_AS_PEER_OBS"
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_OBSERVER_ROWS = 256
MAX_ROW_BYTES = 4096

FIELDS = frozenset(
    {
        "v",
        "observed_at",
        "correlation_id",
        "endpoint",
        "method",
        "path",
        "peer_present",
        "chain_count",
        "pkix",
        "valid_now",
        "client_auth_eku",
        "leaf_sha256",
        "error",
    }
)
ERRORS = frozenset(
    {
        "none",
        "peer_absent",
        "correlation_invalid",
        "peer_validation_failed",
        "no_request_context",
        "request_context_unavailable",
        "request_marker_unavailable",
        "request_unavailable",
        "observer_failure",
    }
)
ENDPOINTS = {
    ("GET", "realms/fapi-demo/.well-known/openid-configuration"): "discovery",
    ("GET", "realms/fapi-demo/protocol/openid-connect/certs"): "jwks",
    ("POST", "realms/fapi-demo/protocol/openid-connect/ext/par/request"): "par",
    ("POST", "realms/fapi-demo/protocol/openid-connect/token"): "token",
    ("POST", "realms/fapi-demo/protocol/openid-connect/revoke"): "revoke",
}
ENDPOINTS_BY_NAME = {name: pair for pair, name in ENDPOINTS.items()}
CONTEXT_ERRORS = frozenset(
    {
        "no_request_context",
        "request_context_unavailable",
        "request_marker_unavailable",
        "request_unavailable",
    }
)
UTC_INSTANT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z"
)
CORRELATION_ID = re.compile(r"[0-9a-f]{32}")
LEAF_SHA256 = re.compile(r"[A-Za-z0-9_-]{43}")
UNSIGNED_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)")


class ObservationError(ValueError):
    """A parse failure with a safe, input-independent error code."""

    _CODES = frozenset(
        {
            "invalid_input",
            "input_too_large",
            "invalid_utf8",
            "too_many_rows",
            "row_too_large",
            "malformed_row",
            "invalid_value",
            "invariant_violation",
        }
    )

    def __init__(self, code: str) -> None:
        if code not in self._CODES:
            code = "malformed_row"
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise ObservationError(code)


def _instant(value: str) -> bool:
    if not UTC_INSTANT.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


def _leaf_digest(value: str) -> bool:
    if not LEAF_SHA256.fullmatch(value):
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error):
        return False
    return len(decoded) == 32 and base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == value


def _fixed_metadata(row: dict[str, object]) -> bool:
    method = row["method"]
    path = row["path"]
    endpoint = row["endpoint"]
    if (method, path, endpoint) == ("unknown", "unknown", "unknown"):
        return True
    return (method, path) in ENDPOINTS and ENDPOINTS[(method, path)] == endpoint


def _no_peer(row: dict[str, object]) -> bool:
    return (
        row["peer_present"] is False
        and row["chain_count"] == 0
        and row["pkix"] is False
        and row["valid_now"] is False
        and row["client_auth_eku"] is False
        and row["leaf_sha256"] == "none"
    )


def _validate_invariants(row: dict[str, object]) -> None:
    error = row["error"]
    correlation = row["correlation_id"]
    known_metadata = (row["method"], row["path"], row["endpoint"]) != (
        "unknown",
        "unknown",
        "unknown",
    )

    if not _fixed_metadata(row):
        _fail("invariant_violation")

    if error in CONTEXT_ERRORS:
        if correlation != "none" or known_metadata or not _no_peer(row):
            _fail("invariant_violation")
        return

    if error == "observer_failure":
        if correlation != "none" and not CORRELATION_ID.fullmatch(str(correlation)):
            _fail("invariant_violation")
        if not _no_peer(row):
            _fail("invariant_violation")
        return

    if error == "correlation_invalid":
        if correlation != "none" or not known_metadata or not _no_peer(row):
            _fail("invariant_violation")
        return

    if not CORRELATION_ID.fullmatch(str(correlation)) or not known_metadata:
        _fail("invariant_violation")

    if error == "peer_absent":
        if not _no_peer(row):
            _fail("invariant_violation")
        return

    if row["peer_present"] is not True or not 1 <= int(row["chain_count"]) <= 16:
        _fail("invariant_violation")
    if not _leaf_digest(str(row["leaf_sha256"])):
        _fail("invariant_violation")

    all_checks_pass = (
        row["pkix"] is True
        and row["valid_now"] is True
        and row["client_auth_eku"] is True
    )
    if (error == "none") != all_checks_pass:
        _fail("invariant_violation")


def _parse_row(line: str, marker_at: int) -> dict[str, object]:
    prefix = line[:marker_at]
    if not prefix.strip() or not prefix[-1].isspace():
        _fail("malformed_row")
    body = line[marker_at + len(MARKER) :]
    if not body or not body[0].isspace():
        _fail("malformed_row")

    parsed: dict[str, str] = {}
    for token in body.split():
        if token.count("=") != 1:
            _fail("malformed_row")
        key, value = token.split("=", 1)
        if key not in FIELDS or key in parsed:
            _fail("malformed_row")
        parsed[key] = value
    if parsed.keys() != FIELDS:
        _fail("malformed_row")

    if parsed["v"] != "1":
        _fail("invalid_value")
    if not _instant(parsed["observed_at"]):
        _fail("invalid_value")

    correlation = parsed["correlation_id"]
    if correlation != "none" and not CORRELATION_ID.fullmatch(correlation):
        _fail("invalid_value")

    method, path, endpoint = parsed["method"], parsed["path"], parsed["endpoint"]
    if endpoint != "unknown" and (
        endpoint not in ENDPOINTS_BY_NAME
        or ENDPOINTS_BY_NAME[endpoint] != (method, path)
    ):
        _fail("invalid_value")
    if endpoint == "unknown" and (method, path) != ("unknown", "unknown"):
        _fail("invalid_value")

    if parsed["error"] not in ERRORS:
        _fail("invalid_value")
    if parsed["leaf_sha256"] != "none" and not _leaf_digest(parsed["leaf_sha256"]):
        _fail("invalid_value")

    row: dict[str, object] = {
        "v": 1,
        "observed_at": parsed["observed_at"],
        "correlation_id": correlation,
        "endpoint": endpoint,
        "method": method,
        "path": path,
        "peer_present": _parse_bool(parsed["peer_present"]),
        "chain_count": _parse_chain_count(parsed["chain_count"]),
        "pkix": _parse_bool(parsed["pkix"]),
        "valid_now": _parse_bool(parsed["valid_now"]),
        "client_auth_eku": _parse_bool(parsed["client_auth_eku"]),
        "leaf_sha256": parsed["leaf_sha256"],
        "error": parsed["error"],
    }
    _validate_invariants(row)
    return row


def _parse_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    _fail("invalid_value")


def _parse_chain_count(value: str) -> int:
    if not UNSIGNED_INTEGER.fullmatch(value):
        _fail("invalid_value")
    count = int(value)
    if count > 16:
        _fail("invalid_value")
    return count


def parse_observer_rows(logs: bytes) -> list[dict[str, object]]:
    """Extract and validate all observer rows, failing closed on malformed rows."""
    if not isinstance(logs, bytes):
        _fail("invalid_input")
    if len(logs) > MAX_LOG_BYTES:
        _fail("input_too_large")
    try:
        text = logs.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail("invalid_utf8")

    rows: list[dict[str, object]] = []
    for line in text.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        occurrences = line.count(MARKER)
        if not occurrences:
            continue
        if occurrences != 1:
            _fail("malformed_row")
        if len(line.encode("utf-8")) > MAX_ROW_BYTES:
            _fail("row_too_large")
        if len(rows) >= MAX_OBSERVER_ROWS:
            _fail("too_many_rows")
        rows.append(_parse_row(line, line.index(MARKER)))
    return rows
