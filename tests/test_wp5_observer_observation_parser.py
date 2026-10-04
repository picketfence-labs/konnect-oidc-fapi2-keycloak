#!/usr/bin/env python3
"""Validation tests for the fixed WP5 observer log format."""

from __future__ import annotations

import base64
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PARSER_PATH = ROOT / "tests/harness/wp5_observer/observation_parser.py"
SPEC = importlib.util.spec_from_file_location("wp5_observation_parser_test", PARSER_PATH)
assert SPEC is not None and SPEC.loader is not None
parser = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(parser)

PREFIX = "2026-10-04 12:34:56,789 INFO  [org.keycloak.example] (executor-thread-1) "
LEAF = base64.urlsafe_b64encode(bytes(32)).decode("ascii").rstrip("=")
FIELDS = {
    "v": "1",
    "observed_at": "2026-10-04T03:04:05.123456789Z",
    "correlation_id": "0123456789abcdef0123456789abcdef",
    "endpoint": "token",
    "method": "POST",
    "path": "realms/fapi-demo/protocol/openid-connect/token",
    "peer_present": "true",
    "chain_count": "2",
    "pkix": "true",
    "valid_now": "true",
    "client_auth_eku": "true",
    "leaf_sha256": LEAF,
    "error": "none",
}


def line(overrides: dict[str, str] | None = None, *, duplicate: str | None = None) -> bytes:
    values = {**FIELDS, **(overrides or {})}
    tokens = [f"{key}={value}" for key, value in values.items()]
    if duplicate is not None:
        tokens.append(duplicate)
    return (PREFIX + parser.MARKER + " " + " ".join(tokens) + "\n").encode("utf-8")


def expect_parse_error(test: unittest.TestCase, logs: bytes, code: str | None = None) -> parser.ObservationError:
    with test.assertRaises(parser.ObservationError) as caught:
        parser.parse_observer_rows(logs)
    if code is not None:
        test.assertEqual(caught.exception.code, code)
    test.assertIn(caught.exception.code, parser.ObservationError._CODES)
    return caught.exception


class ObservationParserTests(unittest.TestCase):
    def test_parses_prefixed_valid_row_and_ignores_other_logs(self) -> None:
        logs = b"startup message\n" + line() + b"request completed\n"
        rows = parser.parse_observer_rows(logs)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["v"], 1)
        self.assertEqual(row["observed_at"], FIELDS["observed_at"])
        self.assertEqual(row["correlation_id"], FIELDS["correlation_id"])
        self.assertEqual((row["endpoint"], row["method"], row["path"]), ("token", "POST", FIELDS["path"]))
        self.assertIs(row["peer_present"], True)
        self.assertEqual(row["chain_count"], 2)
        self.assertEqual((row["pkix"], row["valid_now"], row["client_auth_eku"]), (True, True, True))
        self.assertEqual(row["leaf_sha256"], LEAF)
        self.assertEqual(row["error"], "none")
        self.assertEqual(parser.parse_observer_rows(b"ordinary logs only\n"), [])

    def test_parses_fixed_source_failure_rows(self) -> None:
        absent = {
            "peer_present": "false",
            "chain_count": "0",
            "pkix": "false",
            "valid_now": "false",
            "client_auth_eku": "false",
            "leaf_sha256": "none",
            "error": "peer_absent",
        }
        row = parser.parse_observer_rows(line(absent))[0]
        self.assertEqual(row["error"], "peer_absent")

        context = {
            "correlation_id": "none",
            "endpoint": "unknown",
            "method": "unknown",
            "path": "unknown",
            **absent,
            "error": "no_request_context",
        }
        self.assertEqual(parser.parse_observer_rows(line(context))[0]["error"], "no_request_context")

        bad_correlation = {
            "correlation_id": "none",
            **absent,
            "error": "correlation_invalid",
        }
        self.assertEqual(parser.parse_observer_rows(line(bad_correlation))[0]["error"], "correlation_invalid")

        failed_validation = {
            "pkix": "false",
            "error": "peer_validation_failed",
        }
        self.assertEqual(parser.parse_observer_rows(line(failed_validation))[0]["error"], "peer_validation_failed")

        observer_failure = {
            "peer_present": "false",
            "chain_count": "0",
            "pkix": "false",
            "valid_now": "false",
            "client_auth_eku": "false",
            "leaf_sha256": "none",
            "error": "observer_failure",
        }
        self.assertEqual(parser.parse_observer_rows(line(observer_failure))[0]["error"], "observer_failure")

    def test_rejects_missing_extra_and_duplicate_fields(self) -> None:
        missing = {key: value for key, value in FIELDS.items() if key != "path"}
        missing_line = (PREFIX + parser.MARKER + " " + " ".join(f"{k}={v}" for k, v in missing.items()) + "\n").encode()
        expect_parse_error(self, missing_line, "malformed_row")
        expect_parse_error(self, line()[:-1] + b" extra=value\n", "malformed_row")
        expect_parse_error(self, line(duplicate="v=1"), "malformed_row")
        expect_parse_error(self, line(duplicate="private_value=secret"), "malformed_row")

    def test_rejects_untrusted_enums_and_endpoint_mismatches(self) -> None:
        expect_parse_error(self, line({"error": "sentinel-secret"}), "invalid_value")
        expect_parse_error(self, line({"endpoint": "par"}), "invalid_value")
        expect_parse_error(self, line({"method": "GET"}), "invalid_value")
        expect_parse_error(self, line({"path": "realms/other/token"}), "invalid_value")
        expect_parse_error(self, line({"v": "2"}), "invalid_value")

    def test_rejects_invalid_timestamp_correlation_digest_booleans_and_counts(self) -> None:
        for override in (
            {"observed_at": "2026-02-30T03:04:05Z"},
            {"observed_at": "2026-10-04T03:04:05+00:00"},
            {"correlation_id": "0123456789ABCDEF0123456789abcdef"},
            {"correlation_id": "sentinel-secret"},
            {"leaf_sha256": "not-a-digest"},
            {"peer_present": "True"},
            {"chain_count": "17"},
            {"chain_count": "01"},
        ):
            with self.subTest(override=override):
                expect_parse_error(self, line(override))

    def test_rejects_cross_field_inconsistencies(self) -> None:
        expect_parse_error(self, line({"error": "peer_absent"}), "invariant_violation")
        expect_parse_error(self, line({"error": "none", "pkix": "false"}), "invariant_violation")
        expect_parse_error(self, line({"error": "peer_validation_failed"}), "invariant_violation")
        expect_parse_error(
            self,
            line({"error": "correlation_invalid", "correlation_id": "0123456789abcdef0123456789abcdef"}),
            "invariant_violation",
        )
        expect_parse_error(
            self,
            line({"error": "no_request_context", "endpoint": "token"}),
            "invariant_violation",
        )

    def test_malformed_marker_rows_and_utf8_fail_closed(self) -> None:
        expect_parse_error(self, f"{parser.MARKER} v=1\n".encode(), "malformed_row")
        expect_parse_error(self, (PREFIX + parser.MARKER + " " + parser.MARKER + "\n").encode(), "malformed_row")
        expect_parse_error(self, b"unrelated\xff\n", "invalid_utf8")
        expect_parse_error(self, b"partial utf8 \xe2\x82", "invalid_utf8")

    def test_enforces_log_row_and_line_limits(self) -> None:
        expect_parse_error(self, b"x" * (parser.MAX_LOG_BYTES + 1), "input_too_large")
        long_row = PREFIX + parser.MARKER + " " + ("x" * parser.MAX_ROW_BYTES)
        expect_parse_error(self, (long_row + "\n").encode(), "row_too_large")
        expect_parse_error(self, line() * (parser.MAX_OBSERVER_ROWS + 1), "too_many_rows")

    def test_errors_never_echo_input_values(self) -> None:
        sentinel = "TOP-SECRET-DO-NOT-ECHO-88c4"
        error = expect_parse_error(self, line({"error": sentinel}), "invalid_value")
        self.assertNotIn(sentinel, str(error))
        self.assertNotIn(sentinel, repr(error.args))
        self.assertEqual(error.args, ("invalid_value",))


if __name__ == "__main__":
    unittest.main()
