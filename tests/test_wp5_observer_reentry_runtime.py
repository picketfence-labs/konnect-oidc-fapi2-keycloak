#!/usr/bin/env python3
"""Offline acceptance checks for the isolated three-mode runtime matrix."""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "harness" / "wp5_observer"))
import reentry_runtime_fixture as fixture  # noqa: E402


PAR_PATH = fixture.PAR_PATH
CID = "a" * 32
THUMB = "A" * 43
PREFIX = "2026-10-04T00:00:00Z INFO "


def observer_row(cid: str = CID) -> bytes:
    return (PREFIX + "WP5_AS_PEER_OBS v=1 observed_at=2026-10-04T00:00:00Z "
            f"correlation_id={cid} endpoint=par method=POST path={PAR_PATH} "
            f"peer_present=true chain_count=1 pkix=true valid_now=true client_auth_eku=true "
            f"leaf_sha256={THUMB} error=none\n").encode("ascii")


def reentry_row(count: int, cid: str = CID) -> bytes:
    return (PREFIX + f"WP5_AS_PEER_REENTRY v=1 correlation_id={cid} endpoint=par "
            f"method=POST path={PAR_PATH} count={count}\n").encode("ascii")


class ReentryRuntimeMatrixTests(unittest.TestCase):
    def test_compose_contract_uses_dedicated_default_bridge(self):
        contract = fixture._compose_config_contract()
        self.assertFalse(contract["network_internal"])
        self.assertEqual(contract["network_driver"], "default_bridge")
        self.assertEqual(contract["loopback_mapping"], "127.0.0.1:19443:8443")

    def test_observer_only_mode_requires_one_healthy_route_b_peer_row(self):
        result = fixture.validate_mode_logs(fixture.MODES[0], CID, THUMB, observer_row())
        self.assertEqual((result["observer_rows"], result["reentry_rows"]), (1, 0))
        self.assertEqual(set(result["observer_evidence"]), {
            "v", "observed_at", "correlation_id", "endpoint", "method", "path", "peer_present",
            "chain_count", "pkix", "valid_now", "client_auth_eku", "leaf_sha256", "error",
        })

    def test_canonical_peer_evidence_requires_nonempty_chain(self):
        row = fixture.base_runtime.parse_observer_logs(observer_row())[0]
        row["chain_count"] = 0
        with self.assertRaises(fixture.ReentryFixtureError) as caught:
            fixture._validate_healthy_observer([row], CID, THUMB)
        self.assertEqual(caught.exception.code, "observer_mode_join_invalid")

    def test_probe_mode_requires_canonical_join_and_contiguous_reentry(self):
        logs = observer_row() + reentry_row(2) + reentry_row(3)
        result = fixture.validate_mode_logs(fixture.MODES[1], CID, THUMB, logs)
        self.assertEqual((result["observer_rows"], result["reentry_counts"]), (1, [2, 3]))

    def test_probe_mode_rejects_a_noncontiguous_reentry_sequence(self):
        with self.assertRaises(fixture.ReentryFixtureError) as caught:
            fixture.validate_mode_logs(fixture.MODES[1], CID, THUMB,
                                       observer_row() + reentry_row(2) + reentry_row(4))
        self.assertEqual(caught.exception.code, "reentry_parse_failed")

    def test_both_disabled_mode_requires_zero_marker_rows(self):
        result = fixture.validate_mode_logs(fixture.MODES[2], CID, THUMB, b"no marker rows\n")
        self.assertEqual((result["observer_rows"], result["reentry_rows"]), (0, 0))

    def test_all_modes_require_equal_par_negative_statuses_and_distinct_ids(self):
        rows = [{"http_status": 401, "correlation_id": cid} for cid in ("a" * 32, "b" * 32, "c" * 32)]
        self.assertEqual(fixture.validate_three_mode_statuses(rows), 401)
        rows[-1]["correlation_id"] = rows[0]["correlation_id"]
        with self.assertRaises(fixture.ReentryFixtureError):
            fixture.validate_three_mode_statuses(rows)

    def test_port_wait_stops_at_absolute_runtime_deadline(self):
        with patch.object(fixture, "_port_is_free", return_value=False):
            self.assertFalse(fixture._wait_port_released(deadline=time.monotonic() - 1))


if __name__ == "__main__":
    unittest.main()
