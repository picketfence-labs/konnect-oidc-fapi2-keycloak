#!/usr/bin/env python3
"""Focused offline trust-boundary tests for the WP5 5c runtime fixture."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests/harness/wp5_observer"
sys.path.insert(0, str(HARNESS))
import transport_fixture as fixture  # noqa: E402


def _digest(byte: bytes) -> str:
    return base64.urlsafe_b64encode(byte * 32).decode("ascii").rstrip("=")


def _wire(rid: str, endpoint: str, identity: str, *, grant: str = "none",
          token_kind: str = "unspecified", status: int | None = None,
          extended: bool = False, second_refresh: bool = False) -> dict:
    route = "A" if identity == "route_A" else "B" if identity == "route_B" else "none"
    status = status if status is not None else 201 if endpoint == "par" else 200
    is_b = identity == "route_B"
    claim = ({"alg": "PS256", "aud_is_issuer": True, "iss_sub_match": True,
              "ttl_seconds": 60, "jti_present": True, "jti_distinct": True}
             if is_b else {"alg": "unknown", "aud_is_issuer": False, "iss_sub_match": False,
                           "ttl_seconds": 0, "jti_present": False, "jti_distinct": False})
    is_token = endpoint == "token"
    is_revoke = endpoint == "revocation"
    row = {
        "v": 1, "request_id": rid, "endpoint_kind": endpoint,
        "method": fixture.ENDPOINTS[endpoint][0], "logical_route": route,
        "identity_kind": identity, "status": status,
        "client_cert_present": True, "client_key_present": True,
        "client_assertion_present": is_b, "client_assertion_type_present": is_b,
        "grant_type": grant, "token_kind": token_kind, "assertion": claim,
        "token_present": is_token, "refresh_token_present": is_token,
        "cnf_matches": is_token, "revoke_token_present": is_revoke,
        "oauth_error_enum": "none",
    }
    if extended:
        row["par_evidence"] = {
            "pkce_s256": endpoint == "par",
            "code_challenge_present": endpoint == "par",
            "nonce_present": endpoint == "par",
            "nonce_at_most_64": endpoint == "par",
            "callback_uri_fixed": endpoint == "par",
        }
        row["refresh_evidence"] = {
            "input_matches_previous": grant == "refresh_token",
            "output_differs_from_input": grant == "refresh_token",
            "second_uses_rotated": grant == "refresh_token" and second_refresh,
        }
    return row


def _context(wire: dict) -> dict:
    return {
        "request_id": wire["request_id"], "logical_route": wire["logical_route"],
        "endpoint_kind": wire["endpoint_kind"], "method": wire["method"],
        "identity_kind": wire["identity_kind"],
        "oauth_auth_method": "tls_client_auth" if wire["identity_kind"] == "route_A" else "private_key_jwt",
        "result": "response_received", "not_sent": False, "http_status": wire["status"],
        **({"grant_type": wire["grant_type"], "token_kind": wire["token_kind"]}
           if wire["endpoint_kind"] in {"token", "revocation"} else {}),
        **({"claim_summary": {key: wire["assertion"][key] for key in (
            "alg", "aud_is_issuer", "iss_sub_match", "ttl_seconds", "jti_present",
        )}} if wire["identity_kind"] == "route_B" else {}),
    }


def _valid_matrix(*, extended: bool = False):
    wire_rows = []
    context_rows = []
    observer_rows = []
    next_id = 1
    route_leaf = {"route_A": _digest(b"A"), "route_B": _digest(b"B"), "metadata": _digest(b"M")}
    endpoint_to_observer = {
        "discovery": ("discovery", "GET", "realms/fapi-demo/.well-known/openid-configuration"),
        "jwks": ("jwks", "GET", "realms/fapi-demo/protocol/openid-connect/certs"),
        "par": ("par", "POST", "realms/fapi-demo/protocol/openid-connect/ext/par/request"),
        "token": ("token", "POST", "realms/fapi-demo/protocol/openid-connect/token"),
        "revocation": ("revoke", "POST", "realms/fapi-demo/protocol/openid-connect/revoke"),
    }

    refresh_seen = {"route_A": 0, "route_B": 0}

    def add(endpoint, identity, *, grant="none", token_kind="unspecified", status=None):
        nonlocal next_id
        rid = f"{next_id:032x}"
        next_id += 1
        second_refresh = False
        if grant == "refresh_token":
            refresh_seen[identity] += 1
            second_refresh = refresh_seen[identity] == 2
        wire = _wire(rid, endpoint, identity, grant=grant, token_kind=token_kind, status=status,
                     extended=extended, second_refresh=second_refresh)
        wire_rows.append(wire)
        if identity != "metadata":
            context_rows.append(_context(wire))
        observer_endpoint, method, path = endpoint_to_observer[endpoint]
        observer_rows.append({
            "v": 1, "observed_at": "2026-10-04T00:00:00Z", "correlation_id": rid,
            "endpoint": observer_endpoint, "method": method, "path": path,
            "peer_present": True, "chain_count": 2, "pkix": True, "valid_now": True,
            "client_auth_eku": True, "leaf_sha256": route_leaf[identity], "error": "none",
        })

    add("discovery", "metadata", status=200)
    add("jwks", "metadata", status=200)
    for identity in ("route_A", "route_B"):
        add("par", identity, status=201)
        add("token", identity, grant="authorization_code", status=200)
        add("token", identity, grant="refresh_token", status=200)
        if extended:
            add("token", identity, grant="refresh_token", status=200)
        add("revocation", identity, token_kind="access_token", status=200)
        add("revocation", identity, token_kind="refresh_token", status=200)
    prepared = {"expected_leaf_sha256": {
        "route_a": route_leaf["route_A"], "route_b": route_leaf["route_B"],
        "metadata": route_leaf["metadata"],
    }}
    markers = [{"v": 1, "observations": context_rows, "truncated": False}]
    return wire_rows, markers, observer_rows, prepared


class TransportFixtureTests(unittest.TestCase):
    def test_wire_marker_parser_accepts_timer_suffix_without_retaining_it(self):
        row = _wire("a" * 32, "discovery", "metadata", status=200)
        raw = b"2026/10/04 [error] WP5_TRANSPORT_WIRE=" + json.dumps(row).encode() + b", context: ngx.timer\n"
        parsed = fixture._marker_rows(raw, fixture.WIRE_MARKER, max_rows=fixture.MAX_WIRE_ROWS,
                                      max_row_bytes=16 * 1024)
        self.assertEqual(parsed, [row])
        self.assertNotIn(b"ngx.timer", json.dumps(parsed).encode())

    def test_wire_marker_parser_rejects_duplicate_json_keys_and_duplicate_markers(self):
        duplicate_key = b'{"v":1,"v":1}'
        with self.assertRaises(fixture.TransportFixtureError):
            fixture._marker_rows(fixture.WIRE_MARKER + duplicate_key, fixture.WIRE_MARKER,
                                 max_rows=fixture.MAX_WIRE_ROWS, max_row_bytes=16 * 1024)
        row = json.dumps(_wire("a" * 32, "discovery", "metadata", status=200)).encode()
        with self.assertRaises(fixture.TransportFixtureError):
            fixture._marker_rows(fixture.WIRE_MARKER + row + b" " + fixture.WIRE_MARKER + row,
                                 fixture.WIRE_MARKER, max_rows=fixture.MAX_WIRE_ROWS,
                                 max_row_bytes=16 * 1024)

    def test_join_requires_exact_peer_and_operation_identity_for_full_matrix(self):
        wire, contexts, observer, prep = _valid_matrix()
        joined = fixture._validate_operation_joins(wire, contexts, observer, prep)
        self.assertEqual(joined["operation_join_count"], 12)
        self.assertEqual(joined["route_operation_counts"]["route_a"]["revoke_access"], 1)
        self.assertEqual(joined["route_operation_counts"]["route_b"]["refresh"], 1)
        observer[0]["leaf_sha256"] = _digest(b"X")
        with self.assertRaises(fixture.TransportFixtureError):
            fixture._validate_operation_joins(wire, contexts, observer, prep)

    def test_extended_join_requires_par_fields_and_two_rotating_refreshes_per_route(self):
        wire, contexts, observer, prep = _valid_matrix(extended=True)
        joined = fixture._validate_operation_joins(
            wire, contexts, observer, prep, extended_flow=True,
        )
        self.assertEqual(joined["operation_join_count"], 14)
        self.assertEqual(joined["route_operation_counts"]["route_a"]["refresh"], 2)
        self.assertEqual(joined["route_operation_counts"]["route_b"]["refresh"], 2)

        for field in (
            "pkce_s256", "code_challenge_present", "nonce_present", "nonce_at_most_64", "callback_uri_fixed",
        ):
            with self.subTest(par_field=field):
                wire, contexts, observer, prep = _valid_matrix(extended=True)
                par = next(row for row in wire if row["endpoint_kind"] == "par")
                par["par_evidence"][field] = False
                with self.assertRaisesRegex(fixture.TransportFixtureError, "par_request_profile_gate_failed"):
                    fixture._validate_operation_joins(wire, contexts, observer, prep, extended_flow=True)

        wire, contexts, observer, prep = _valid_matrix(extended=True)
        refreshes = [row for row in wire if row["endpoint_kind"] == "token" and row["grant_type"] == "refresh_token"]
        refreshes[-1]["refresh_evidence"]["second_uses_rotated"] = False
        with self.assertRaisesRegex(fixture.TransportFixtureError, "second_refresh_did_not_use_rotated_token"):
            fixture._validate_operation_joins(wire, contexts, observer, prep, extended_flow=True)

        wire, contexts, observer, prep = _valid_matrix(extended=True)
        refresh = next(row for row in wire if row["endpoint_kind"] == "token" and row["grant_type"] == "refresh_token")
        refresh["refresh_evidence"]["output_differs_from_input"] = False
        with self.assertRaisesRegex(fixture.TransportFixtureError, "refresh_token_rotation_gate_failed"):
            fixture._validate_operation_joins(wire, contexts, observer, prep, extended_flow=True)

    def test_extended_flow_summary_is_bounded_and_requires_iss_rejection_and_two_waits(self):
        metrics = {
            "ok": True, "outcome": "complete", "http_requests": 8, "redirects": 4,
            "status_2xx": 4, "status_3xx": 4, "status_4xx": 1, "status_5xx": 0,
            "login_submissions": 1, "consent_submissions": 0, "callback_completed": True,
            "callback_http_status": 302, "callback_error_enum": "none", "session_cookie_changed": True,
            "phase_callback_called": True, "logout_completed": True,
            "protected_refresh": {"attempted": True, "http_status": 200, "completed": True},
            "extended_evidence": {
                "initial_redirect_query": {
                    "query_names": ["client_id", "request_uri"], "only_expected_names": True,
                    "client_id_matches": True, "request_uri_present": True,
                },
                "callback_iss_mismatch": {"attempted": True, "http_status": 400, "rejected": True},
                "protected_refresh_gets": 2, "refresh_waits": 2,
            },
        }
        safe = fixture._safe_flow_metrics(metrics, extended_flow=True)
        self.assertEqual(safe["extended_evidence"]["protected_refresh_gets"], 2)
        bad = json.loads(json.dumps(metrics))
        bad["extended_evidence"]["callback_iss_mismatch"]["rejected"] = False
        with self.assertRaises(fixture.TransportFixtureError):
            fixture._safe_flow_metrics(bad, extended_flow=True)

    def test_join_fails_on_missing_observer_or_unmatched_context_id(self):
        wire, contexts, observer, prep = _valid_matrix()
        with self.assertRaises(fixture.TransportFixtureError):
            fixture._validate_operation_joins(wire, contexts, observer[:-1], prep)
        wire, contexts, observer, prep = _valid_matrix()
        contexts[0]["observations"].append({**contexts[0]["observations"][0], "request_id": "f" * 32})
        with self.assertRaises(fixture.TransportFixtureError):
            fixture._validate_operation_joins(wire, contexts, observer, prep)

    def test_pre_marker_fixed_routes_must_both_return_503(self):
        body = b'{"error":"client_authentication_unavailable"}'
        with mock.patch.object(fixture, "_require_marker_absent") as marker, \
             mock.patch.object(fixture, "_https_get", side_effect=[(503, body), (503, body)]) as request:
            result = fixture._pre_marker_gate(10**20)
        self.assertEqual(result, {"route_count": 2, "routes": ["A", "B"], "status": 503})
        self.assertEqual([call.args[0] for call in request.call_args_list], [
            "/api/fapi/mtls", "/api/fapi/pkj-mtls",
        ])
        self.assertEqual(marker.call_count, 2)
        with mock.patch.object(fixture, "_require_marker_absent"), \
             mock.patch.object(fixture, "_https_get", return_value=(302, body)):
            with self.assertRaises(fixture.TransportFixtureError):
                fixture._pre_marker_gate(10**20)

    def test_worker_status_gate_rejects_missing_ready_flags_or_wrong_routes(self):
        expected_routes = [
            {"route_id": fixture.ROUTE_IDS["A"], "logical_route": "A", "client_id": fixture.CLIENT_IDS["A"]},
            {"route_id": fixture.ROUTE_IDS["B"], "logical_route": "B", "client_id": fixture.CLIENT_IDS["B"]},
        ]
        row = {"worker_id": 0, "pid": 1234, "generation": "a" * 32,
               "config_hash": "b" * 64, "registry_epoch": "c" * 64,
               "wrapper_ready": True, "registry_ready": True, "bridge_loaded": True,
               "delegate_ready": True, "routes": expected_routes}
        prep = {"generation": "a" * 32}
        with mock.patch.object(fixture, "_exec_kong", return_value=(json.dumps(row) + "\n").encode()):
            self.assertEqual(fixture._read_worker_statuses(prep)[0]["worker_id"], 0)
        bad = {**row, "delegate_ready": False}
        with mock.patch.object(fixture, "_exec_kong", return_value=(json.dumps(bad) + "\n").encode()):
            with self.assertRaises(fixture.TransportFixtureError):
                fixture._read_worker_statuses(prep)

    def test_run_requires_single_attempt_flag_before_any_resource_access(self):
        with mock.patch.object(fixture, "_verify_prepared") as verify:
            with self.assertRaises(fixture.TransportFixtureError):
                fixture.run_fixture()
        verify.assert_not_called()

    def test_consumed_run_intent_is_rejected_before_any_resource_access(self):
        with tempfile.TemporaryDirectory() as directory:
            intent = Path(directory) / "intent.json"
            intent.write_text("{}")
            with mock.patch.object(fixture, "RUN_INTENT", intent), \
                 mock.patch.object(fixture, "RUN_RECEIPT", Path(directory) / "terminal.json"), \
                 mock.patch.object(fixture, "_verify_prepared") as verify:
                with self.assertRaisesRegex(fixture.TransportFixtureError, "run_receipt_path_exists"):
                    fixture.run_fixture(approved_single_attempt=True)
            verify.assert_not_called()

    def test_guard_evidence_rejects_even_one_as_send_or_secret(self):
        clean = {key: [] for key in ("observer_rows", "wire_rows", "context_rows", "context_markers")}
        clean["leak_counts"] = {}
        self.assertTrue(fixture._validate_guard_logs(clean)["as_not_sent"])
        for key in clean:
            with self.subTest(key=key):
                with self.assertRaises(fixture.TransportFixtureError):
                    fixture._validate_guard_logs({**clean, key: {"count": 1} if key == "leak_counts" else [{}]})


if __name__ == "__main__":
    unittest.main()
