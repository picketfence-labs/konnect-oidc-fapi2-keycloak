#!/usr/bin/env python3
"""Focused offline tests for the isolated WP5 re-entry probe variant."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load_module("wp5_reentry_probe_test", "tests/harness/wp5_observer/reentry_probe.py")
parser = load_module("wp5_reentry_parser_test", "tests/harness/wp5_observer/reentry_parser.py")
observer_parser = load_module(
    "wp5_reentry_observation_parser_test", "tests/harness/wp5_observer/observation_parser.py"
)

HELPER_PATH = ROOT / "tests/harness/wp5_observer/observer/AsPeerObserver.java"
CORRELATION = "0123456789abcdef0123456789abcdef"
PAR_PATH = "realms/fapi-demo/protocol/openid-connect/ext/par/request"
PREFIX = "2026-10-04 12:34:56,789 INFO  [org.keycloak.example] (executor-thread-1) "
LEAF = base64.urlsafe_b64encode(bytes(32)).decode("ascii").rstrip("=")


def observer_line(correlation: str = CORRELATION) -> bytes:
    values = {
        "v": "1",
        "observed_at": "2026-10-04T03:04:05.123456789Z",
        "correlation_id": correlation,
        "endpoint": "par",
        "method": "POST",
        "path": PAR_PATH,
        "peer_present": "true",
        "chain_count": "2",
        "pkix": "true",
        "valid_now": "true",
        "client_auth_eku": "true",
        "leaf_sha256": LEAF,
        "error": "none",
    }
    return (PREFIX + observer_parser.MARKER + " " + " ".join(f"{key}={value}" for key, value in values.items()) + "\n").encode()


def reentry_line(count: int, correlation: str = CORRELATION, *, error: str | None = None) -> bytes:
    values = {
        "v": "1",
        "correlation_id": correlation,
        "endpoint": "par",
        "method": "POST",
        "path": PAR_PATH,
        "count": str(count),
    }
    if error is not None:
        values["error"] = error
    return (PREFIX + parser.MARKER + " " + " ".join(f"{key}={value}" for key, value in values.items()) + "\n").encode()


def expect_reentry_error(test: unittest.TestCase, logs: bytes, code: str) -> parser.ReentryError:
    with test.assertRaises(parser.ReentryError) as caught:
        parser.parse_reentry_rows(logs)
    test.assertEqual(caught.exception.code, code)
    test.assertNotIn("TOP-SECRET", str(caught.exception))
    test.assertEqual(caught.exception.args, (code,))
    return caught.exception


class ReentrySourcePatchTests(unittest.TestCase):
    def test_variant_is_anchored_and_keeps_the_v3_source_unchanged(self) -> None:
        original = HELPER_PATH.read_bytes()
        original_digest = hashlib.sha256(original).hexdigest()
        self.assertEqual(original_digest, probe.V3_HELPER_SHA256)

        variant = probe.patch_helper_bytes(original)

        self.assertNotEqual(variant, original)
        self.assertEqual(hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest(), original_digest)
        text = variant.decode("utf-8")
        self.assertIn('"FAPI_DEMO_AS_PEER_REENTRY_PROBE"', text)
        self.assertIn("WP5_AS_PEER_REENTRY v=1", text)
        self.assertIn("count_limit_exceeded", text)
        self.assertIn("MAX_REENTRY_COUNT = 16", text)
        self.assertEqual(text.count("final class AsPeerObserver"), 1)
        self.assertEqual(text.count("AsPeerObserver.class"), original.decode().count("AsPeerObserver.class") + 1)

    def test_probe_stays_after_observer_off_guard_and_adds_no_sensitive_reads(self) -> None:
        original = HELPER_PATH.read_text()
        variant = probe.patch_helper_bytes(original.encode()).decode()
        self.assertLess(variant.index('if (!"true".equals(System.getenv(ENABLED_ENV)))'),
                        variant.index('System.getenv(REENTRY_ENABLED_ENV)'))
        self.assertLess(variant.index('System.getenv(REENTRY_ENABLED_ENV)'),
                        variant.index("CDI.current().select(RoutingContext.class)"))
        self.assertIn("recordReentry(routingContext, reentryProbeEnabled);\n                return;", variant)
        for call in ("getClientCertificateChain()", "getHttpHeaders()", "getDecodedFormParameters()"):
            self.assertEqual(variant.count(call), original.count(call), call)
        self.assertEqual(variant.count("getHttpMethod()"), original.count("getHttpMethod()"))
        self.assertNotIn("getQuery", variant)
        self.assertNotIn("getBody", variant)
        self.assertNotIn("getHeaderString", variant)

    def test_patcher_rejects_changed_source_and_anchor_drift_with_safe_codes(self) -> None:
        source = HELPER_PATH.read_bytes()
        with self.assertRaises(probe.ReentryPatchError) as changed:
            probe.patch_helper_bytes(source + b"x")
        self.assertEqual(changed.exception.code, "source_digest_mismatch")

        mutated = source.replace(b"REQUEST_MARKER", b"REQUEST_LABEL", 1)
        with mock.patch.object(probe, "V3_HELPER_SHA256", hashlib.sha256(mutated).hexdigest()):
            with self.assertRaises(probe.ReentryPatchError) as drift:
                probe.patch_helper_bytes(mutated)
        self.assertEqual(drift.exception.code, "anchor_mismatch")


class ReentryParserTests(unittest.TestCase):
    def test_parses_contiguous_repeat_rows_and_joins_one_healthy_par_observation(self) -> None:
        logs = b"Keycloak ready\n" + observer_line() + reentry_line(2) + reentry_line(3)
        rows = parser.parse_reentry_rows(logs)
        self.assertEqual([row["count"] for row in rows], [2, 3])
        evidence = parser.validate_par_evidence(logs, CORRELATION)
        self.assertEqual(evidence["reentry_count"], 3)
        self.assertEqual(evidence["observer_row"]["endpoint"], "par")
        self.assertEqual(len(evidence["reentry_rows"]), 2)

    def test_off_mode_has_no_reentry_rows_while_observer_row_remains_parseable(self) -> None:
        logs = observer_line()
        self.assertEqual(parser.parse_reentry_rows(logs), [])
        self.assertEqual(len(observer_parser.parse_observer_rows(logs)), 1)
        with self.assertRaises(parser.ReentryError) as missing:
            parser.validate_par_evidence(logs, CORRELATION)
        self.assertEqual(missing.exception.code, "reentry_diagnostic_missing")

    def test_rejects_gaps_duplicates_overflow_and_unknown_record_fields(self) -> None:
        expect_reentry_error(self, reentry_line(2) + reentry_line(4), "count_sequence_invalid")
        expect_reentry_error(self, reentry_line(2) + reentry_line(2), "count_sequence_invalid")
        expect_reentry_error(
            self,
            reentry_line(2) + reentry_line(16, error="count_limit_exceeded"),
            "count_limit_exceeded",
        )
        expect_reentry_error(self, reentry_line(2)[:-1] + b" secret=TOP-SECRET\n", "malformed_row")

    def test_rejects_malformed_ids_paths_counts_and_marker_rows_without_echoing_values(self) -> None:
        expect_reentry_error(self, reentry_line(2, "TOP-SECRET"), "invalid_value")
        expect_reentry_error(self, reentry_line(17), "invalid_value")
        expect_reentry_error(self, reentry_line(2).replace(PAR_PATH.encode(), b"realms/attacker/token"), "invalid_value")
        expect_reentry_error(self, b"startup " + parser.MARKER.encode() + b" nope\n", "malformed_row")
        expect_reentry_error(self, reentry_line(2)[:-1] + b" " + parser.MARKER.encode() + b" v=1\n", "malformed_row")
        expect_reentry_error(self, b"nonutf8 \xff\n", "invalid_utf8")

    def test_requires_exactly_one_matching_canonical_row_for_the_par_request(self) -> None:
        logs = observer_line() + observer_line() + reentry_line(2)
        with self.assertRaises(parser.ReentryError) as duplicated:
            parser.validate_par_evidence(logs, CORRELATION)
        self.assertEqual(duplicated.exception.code, "canonical_row_join_failed")

        mismatch = observer_line() + reentry_line(2, "fedcba9876543210fedcba9876543210")
        with self.assertRaises(parser.ReentryError) as unjoined:
            parser.validate_par_evidence(mismatch, CORRELATION)
        self.assertEqual(unjoined.exception.code, "reentry_diagnostic_missing")

    def test_enforces_byte_row_and_line_caps(self) -> None:
        with mock.patch.object(parser, "MAX_LOG_BYTES", 8):
            expect_reentry_error(self, b"x" * 9, "input_too_large")
        with mock.patch.object(parser, "MAX_REENTRY_ROWS", 1):
            expect_reentry_error(self, reentry_line(2) + reentry_line(3), "too_many_rows")
        oversized = PREFIX + parser.MARKER + " " + "x" * parser.MAX_ROW_BYTES + "\n"
        expect_reentry_error(self, oversized.encode(), "row_too_large")


if __name__ == "__main__":
    unittest.main()
