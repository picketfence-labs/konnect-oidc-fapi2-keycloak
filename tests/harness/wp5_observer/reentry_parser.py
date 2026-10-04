"""Strict parser and join validator for the opt-in WP5 handler re-entry records."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path


MARKER = "WP5_AS_PEER_REENTRY"
OBS_MARKER = "WP5_AS_PEER_OBS"
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_REENTRY_ROWS = 256
MAX_ROW_BYTES = 4096
MAX_COUNT = 16

ENDPOINTS = {
    ("GET", "realms/fapi-demo/.well-known/openid-configuration"): "discovery",
    ("GET", "realms/fapi-demo/protocol/openid-connect/certs"): "jwks",
    ("POST", "realms/fapi-demo/protocol/openid-connect/ext/par/request"): "par",
    ("POST", "realms/fapi-demo/protocol/openid-connect/token"): "token",
    ("POST", "realms/fapi-demo/protocol/openid-connect/revoke"): "revoke",
}
ROW_FIELDS = frozenset({"v", "correlation_id", "endpoint", "method", "path", "count"})
OVERFLOW_FIELDS = ROW_FIELDS | {"error"}
CORRELATION_ID = re.compile(r"[0-9a-f]{32}\Z")
UNSIGNED_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z")


class ReentryError(ValueError):
    """A parse or evidence-join failure with a safe constant code."""

    _CODES = frozenset(
        {
            "invalid_input",
            "input_too_large",
            "invalid_utf8",
            "too_many_rows",
            "row_too_large",
            "malformed_row",
            "invalid_value",
            "count_limit_exceeded",
            "count_sequence_invalid",
            "observer_rows_invalid",
            "canonical_row_join_failed",
            "par_evidence_invalid",
            "reentry_diagnostic_missing",
            "correlation_invalid",
        }
    )

    def __init__(self, code: str) -> None:
        if code not in self._CODES:
            code = "malformed_row"
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise ReentryError(code)


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
        if key not in OVERFLOW_FIELDS or key in parsed:
            _fail("malformed_row")
        parsed[key] = value

    has_error = "error" in parsed
    expected_fields = OVERFLOW_FIELDS if has_error else ROW_FIELDS
    if parsed.keys() != expected_fields:
        _fail("malformed_row")
    if parsed["v"] != "1":
        _fail("invalid_value")

    correlation = parsed["correlation_id"]
    if not CORRELATION_ID.fullmatch(correlation):
        _fail("invalid_value")
    method, path, endpoint = parsed["method"], parsed["path"], parsed["endpoint"]
    if ENDPOINTS.get((method, path)) != endpoint:
        _fail("invalid_value")
    if not UNSIGNED_INTEGER.fullmatch(parsed["count"]):
        _fail("invalid_value")
    count = int(parsed["count"])

    if has_error:
        if parsed["error"] != "count_limit_exceeded" or count != MAX_COUNT:
            _fail("invalid_value")
    elif not 2 <= count <= MAX_COUNT:
        _fail("invalid_value")

    row: dict[str, object] = {
        "v": 1,
        "correlation_id": correlation,
        "endpoint": endpoint,
        "method": method,
        "path": path,
        "count": count,
    }
    if has_error:
        row["error"] = "count_limit_exceeded"
    return row


def parse_reentry_rows(logs: bytes) -> list[dict[str, object]]:
    """Parse fixed re-entry rows and require contiguous counts per correlation ID."""
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
        if occurrences != 1 or OBS_MARKER in line:
            _fail("malformed_row")
        if len(line.encode("utf-8")) > MAX_ROW_BYTES:
            _fail("row_too_large")
        if len(rows) >= MAX_REENTRY_ROWS:
            _fail("too_many_rows")
        rows.append(_parse_row(line, line.index(MARKER)))

    grouped: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        if "error" in row:
            _fail("count_limit_exceeded")
        grouped.setdefault(str(row["correlation_id"]), []).append(row)

    for group in grouped.values():
        metadata = (group[0]["endpoint"], group[0]["method"], group[0]["path"])
        counts = [int(row["count"]) for row in group]
        if any((row["endpoint"], row["method"], row["path"]) != metadata for row in group):
            _fail("count_sequence_invalid")
        if counts != list(range(2, 2 + len(counts))):
            _fail("count_sequence_invalid")
    return rows


def _observation_parser():
    path = Path(__file__).with_name("observation_parser.py")
    spec = importlib.util.spec_from_file_location("wp5_reentry_observer_parser", path)
    if spec is None or spec.loader is None:
        _fail("observer_rows_invalid")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_par_evidence(logs: bytes, correlation_id: str) -> dict[str, object]:
    """Require one healthy PAR observer row joined to a repeated-handler sequence."""
    if not isinstance(logs, bytes):
        _fail("invalid_input")
    if not CORRELATION_ID.fullmatch(correlation_id):
        _fail("correlation_invalid")
    reentry_rows = parse_reentry_rows(logs)
    try:
        observer_rows = _observation_parser().parse_observer_rows(logs)
    except Exception:
        _fail("observer_rows_invalid")

    canonical = [row for row in observer_rows if row["correlation_id"] == correlation_id]
    if len(canonical) != 1:
        _fail("canonical_row_join_failed")
    observer = canonical[0]
    if (
        observer["endpoint"] != "par"
        or observer["method"] != "POST"
        or observer["path"] != "realms/fapi-demo/protocol/openid-connect/ext/par/request"
        or observer["error"] != "none"
        or observer["peer_present"] is not True
        or observer["pkix"] is not True
        or observer["valid_now"] is not True
        or observer["client_auth_eku"] is not True
        or observer["leaf_sha256"] == "none"
    ):
        _fail("par_evidence_invalid")

    joined = [row for row in reentry_rows if row["correlation_id"] == correlation_id]
    if not joined:
        _fail("reentry_diagnostic_missing")
    expected = (observer["endpoint"], observer["method"], observer["path"])
    if any((row["endpoint"], row["method"], row["path"]) != expected for row in joined):
        _fail("canonical_row_join_failed")
    return {
        "observer_row": observer,
        "reentry_rows": joined,
        "reentry_count": int(joined[-1]["count"]),
    }
