from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/harness/wp5_observer"))
import stock_fixture as fixture


class StockFixtureTests(unittest.TestCase):
    def _prepared(self):
        # Unit fixtures use the host temp directory. Runner tests stub the
        # live cleanup guard, whose /private/tmp target remains fixed.
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        root.rmdir()  # prepare_stock_fixture must claim a new, exclusive path.
        prep = root.parent / f".{root.name}-prep.json"
        with mock.patch.dict(os.environ, {"KONG_LICENSE_DATA": '{"license":{"fixture":"test-only"}}'}):
            receipt = fixture.prepare_stock_fixture(root, prep)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        self.addCleanup(lambda: prep.unlink(missing_ok=True))
        self.addCleanup(directory.cleanup)
        return root, prep, receipt

    def test_preparation_is_private_bounded_and_uses_only_three_services(self):
        root, prep_path, receipt = self._prepared()
        self.assertEqual(receipt["schema"], "wp5-stock-par-prep-v15")
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(receipt["files"]["license/license.json"]["mode"], "0600")
        self.assertEqual((root / "license/license.json").read_bytes(), b'{"license":{"fixture":"test-only"}}')
        self.assertNotIn(b"test-only", prep_path.read_bytes())
        compose = (root / "compose.yml").read_text(encoding="utf-8")
        service_names = ("  keycloak:\n", "  kong:\n", "  as-spike-harness:\n")
        self.assertEqual(sum(compose.count(name) for name in service_names), 3)
        self.assertIn('127.0.0.1:8444:8443', compose)
        self.assertIn('127.0.0.1:8443:8443', compose)
        self.assertIn('127.0.0.1:19445:9443', compose)
        self.assertNotIn("internal: true", compose)
        self.assertIn("name: wp5-stock-par-route-b-v15_default", compose)
        self.assertIn("KONG_LICENSE_PATH: /run/wp5/license.json", compose)
        self.assertIn("KONG_LOG_LEVEL: error", compose)
        self.assertIn("KONG_PROXY_ERROR_LOG: /dev/stderr", compose)
        self.assertIn("as-host-gateway:host-gateway", compose)
        self.assertNotIn(".env", compose)
        self.assertNotIn("konnect", compose.lower())
        self.assertEqual(fixture.verify_prepared_fixture(root, prep_path)["file_count"], receipt["file_count"])
        kong_doc = json.loads((root / "kong/kong.json").read_bytes())
        self.assertEqual(kong_doc["plugins"], [{"name": "wp5-stock-token-diag", "config": {}}])
        oidc_config = next(
            plugin["config"] for service in kong_doc["services"]
            for plugin in service["plugins"] if plugin["name"] == "openid-connect"
        )
        self.assertIsNone(oidc_config["login_tokens"])
        self.assertTrue((root / "plugins/wp5-stock-token-diag/handler.lua").is_file())
        self.assertTrue((root / "plugins/wp5-stock-token-diag/schema.lua").is_file())
        realm = json.loads((root / "realm/fapi-demo-realm.json").read_bytes())
        self.assertEqual(realm["defaultSignatureAlgorithm"], "PS256")
        ps256_provider = realm["components"]["org.keycloak.keys.KeyProvider"]
        self.assertEqual(ps256_provider, [{
            "name": "wp5-ps256", "providerId": "rsa-generated",
            "config": {
                "priority": ["100"], "enabled": ["true"], "active": ["true"],
                "algorithm": ["PS256"], "keySize": ["3072"],
            },
        }])
        client = realm["clients"][0]
        self.assertEqual(client["attributes"]["jwt.credential.kid"], receipt["jwk_kid"])
        self.assertEqual(client["attributes"]["post.logout.redirect.uris"], "https://localhost:3443/?logout=route-b")
        self.assertEqual(realm["users"][0]["username"], fixture.DEMO_USERNAME)
        self.assertEqual(realm["users"][0]["firstName"], "WP5")
        self.assertEqual(realm["users"][0]["lastName"], "Demo")
        self.assertEqual(realm["users"][0]["email"], fixture.DEMO_USERNAME + "@example.invalid")
        self.assertEqual(len(realm["users"][0]["credentials"]), 1)
        user_password = realm["users"][0]["credentials"][0]["value"]
        self.assertIn(user_password.encode(), fixture._candidate_secrets(root))
        self.assertNotIn(user_password, prep_path.read_text())

    def test_fixture_verification_detects_mutation_and_cleanup_rejects_other_paths(self):
        root, prep_path, _receipt = self._prepared()
        target = root / "realm/fapi-demo-realm.json"
        target.write_bytes(target.read_bytes() + b" ")
        with self.assertRaisesRegex(fixture.StockFixtureError, "prep_file_manifest_mismatch"):
            fixture.verify_prepared_fixture(root, prep_path)
        other = root.parent / f"{root.name}-other"
        other.mkdir(mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(other, ignore_errors=True))
        with self.assertRaisesRegex(fixture.StockFixtureError, "fixture_cleanup_path_mismatch"):
            fixture._remove_fixture(other)
        self.assertTrue(other.is_dir())

    def test_non_302_relay_diagnostic_snapshot_is_sanitized(self):
        event = {
            "operation_id": "a" * 32, "operation": "par", "stage": "par_claim_gate",
            "endpoint": "par", "method": "POST", "path": fixture.PAR_PATH,
            "algorithm": "unknown", "audience_is_issuer": False, "issuer_subject_match": False,
            "ttl_seconds": 0, "remaining_ttl_seconds": 0, "jti_distinct": False,
            "stock_form_client_id_present": False,
            "token_kind": "not_applicable", "relay_attempted": False, "forwarded": False,
            "token_distinct": True, "http_status": 0, "oauth_error_enum": "none",
            "result": "assertion_audience",
        }
        snapshot = {"stage": "par_claim_gate", "failed": True, "overflow": False, "events": [event]}
        safe = fixture._safe_relay_snapshot(snapshot)
        self.assertEqual(safe["events"][0]["result"], "assertion_audience")
        self.assertNotIn('"jti":', json.dumps(safe))
        with self.assertRaisesRegex(fixture.StockFixtureError, "relay_snapshot_schema_invalid"):
            fixture._safe_relay_snapshot({**snapshot, "events": [{**event, "raw": "secret"}]})

    def test_par_gate_requires_attempted_and_successfully_forwarded_request(self):
        snapshot = {"stage": "par_complete", "failed": False, "overflow": False, "events": []}
        with self.assertRaisesRegex(fixture.StockFixtureError, "stock_par_event_count"):
            fixture._validate_par_event(snapshot)
        event = {
            "operation_id": "a" * 32, "operation": "par", "stage": "par_claim_gate",
            "endpoint": "par", "method": "POST", "path": fixture.PAR_PATH,
            "algorithm": "PS256", "audience_is_issuer": True, "issuer_subject_match": True,
            "ttl_seconds": 60, "remaining_ttl_seconds": 55, "jti_distinct": True,
            "stock_form_client_id_present": False,
            "token_kind": "not_applicable", "relay_attempted": False, "forwarded": True,
            "token_distinct": True, "http_status": 201, "oauth_error_enum": "none", "result": "as_accepted",
        }
        snapshot["events"] = [event]
        with self.assertRaisesRegex(fixture.StockFixtureError, "stock_par_claim_gate_failed"):
            fixture._validate_par_event(snapshot)

        event["relay_attempted"] = True
        event["result"] = "as_accepted"
        snapshot["failed"] = False
        accepted = fixture._validate_par_event(snapshot)
        self.assertFalse(accepted["stock_form_client_id_present"])
        self.assertFalse(accepted["rfc9126_client_id_requirement_met"])
        event["stock_form_client_id_present"] = True
        self.assertTrue(fixture._validate_par_event(snapshot)["rfc9126_client_id_requirement_met"])

    def test_runner_requires_explicit_single_attempt_and_fixed_paths_before_docker(self):
        with mock.patch.object(fixture, "preflight_absent") as preflight:
            with self.assertRaisesRegex(fixture.StockFixtureError, "single_attempt_flag_required"):
                fixture.run_stock_par()
            self.assertEqual(preflight.call_count, 0)
        with mock.patch.object(fixture, "FIXTURE_ROOT", Path("/private/tmp/fixed")):
            with self.assertRaisesRegex(fixture.StockFixtureError, "runtime_paths_not_fixed"):
                fixture.run_stock_par(Path("/private/tmp/other"), approved_single_attempt=True)

    def test_startup_watch_stops_early_for_only_the_owned_kong_container(self):
        container_id = "a" * 64
        status = "{}|{}|kong|{}|{}|{}|exited|127\n".format(
            container_id,
            fixture.PROJECT, fixture.OWNER, fixture.PHASE, fixture.KONG_IMAGE_ID,
        ).encode("ascii")
        with mock.patch.object(fixture, "_rtk_docker", return_value=["docker"]), \
             mock.patch.object(fixture, "_command", side_effect=[container_id.encode() + b"\n", status]) as command:
            with self.assertRaisesRegex(fixture.StockFixtureError, "kong_container_exited"):
                fixture._check_kong_start_state(time.monotonic() + 30)
        self.assertEqual(command.call_count, 2)
        self.assertIn("--no-trunc", command.call_args_list[0].args[0])
        self.assertEqual(command.call_args_list[0].kwargs["timeout"], 10)
        self.assertEqual(command.call_args_list[1].args[0][-1], container_id)

    def test_startup_watch_rejects_short_container_ids_and_retries_transient_timeout(self):
        with mock.patch.object(fixture, "_rtk_docker", return_value=["docker"]), \
             mock.patch.object(fixture, "_command", return_value=b"a" * 12 + b"\n") as command:
            with self.assertRaisesRegex(fixture.StockFixtureError, "kong_container_identity_unavailable"):
                fixture._check_kong_start_state(time.monotonic() + 30)
        self.assertEqual(command.call_count, 1)

        with mock.patch.object(fixture, "_rtk_docker", return_value=["docker"]), \
             mock.patch.object(fixture, "_command", side_effect=fixture.StockFixtureError("command_timeout")):
            self.assertFalse(fixture._check_kong_start_state(time.monotonic() + 30))

    def test_version_fifteen_names_are_isolated_and_entrypoint_matches_pinned_image(self):
        self.assertEqual(fixture.PROJECT, "wp5-stock-par-route-b-v15")
        self.assertEqual(fixture.VOLUME, "wp5-stock-par-route-b-v15-data")
        self.assertEqual(str(fixture.FIXTURE_ROOT), "/private/tmp/wp5-as-peer-stock-par-route-b-20261004-v15")
        entrypoint = (ROOT / "tests/harness/wp5_observer/stock_kong_entrypoint.sh").read_text()
        self.assertIn("exec /entrypoint.sh kong docker-start", entrypoint)
        self.assertNotIn("/docker-entrypoint.sh", entrypoint)

    def test_final_stock_operation_set_requires_par_and_distinct_access_refresh_revokes(self):
        base = {
            "operation_id": "a" * 32, "operation": "par", "stage": "par_claim_gate",
            "endpoint": "par", "method": "POST", "path": fixture.PAR_PATH,
            "algorithm": "PS256", "audience_is_issuer": True, "issuer_subject_match": True,
            "ttl_seconds": 60, "remaining_ttl_seconds": 55, "jti_distinct": True,
            "token_kind": "not_applicable", "relay_attempted": True, "forwarded": True,
            "token_distinct": True, "http_status": 201, "oauth_error_enum": "none",
            "stock_form_client_id_present": False, "result": "as_accepted",
        }
        revoke_access = {**base, "operation_id": "b" * 32, "operation": "revoke",
                         "stage": "session_logout", "endpoint": "revoke",
                         "path": "/realms/fapi-demo/protocol/openid-connect/revoke",
                         "token_kind": "access_token", "http_status": 200}
        revoke_refresh = {**revoke_access, "operation_id": "c" * 32, "token_kind": "refresh_token"}
        snapshot = {"stage": "session_logout", "failed": False, "overflow": False,
                    "events": [base, revoke_access, revoke_refresh]}
        events = fixture._validate_stock_operations(snapshot)
        self.assertEqual([item["operation"] for item in events], ["par", "revoke", "revoke"])
        self.assertEqual({item["token_kind"] for item in events[1:]}, {"access_token", "refresh_token"})
        with self.assertRaisesRegex(fixture.StockFixtureError, "stock_operation_id_duplicate"):
            fixture._validate_stock_operations({**snapshot, "events": [base, revoke_access, revoke_access]})
        with self.assertRaisesRegex(fixture.StockFixtureError, "stock_revoke_acceptance_failed"):
            fixture._validate_stock_operations({**snapshot, "events": [base, revoke_access, {**revoke_refresh, "http_status": 401}]})

    def test_three_stock_operations_require_one_to_one_route_b_peer_joins(self):
        base = {
            "operation_id": "a" * 32, "operation": "par", "stage": "par_claim_gate",
            "endpoint": "par", "method": "POST", "path": fixture.PAR_PATH,
            "algorithm": "PS256", "audience_is_issuer": True, "issuer_subject_match": True,
            "ttl_seconds": 60, "remaining_ttl_seconds": 55, "jti_distinct": True,
            "token_kind": "not_applicable", "relay_attempted": True, "forwarded": True,
            "token_distinct": True, "http_status": 201, "oauth_error_enum": "none",
            "stock_form_client_id_present": False, "result": "as_accepted",
        }
        events = [base,
                  {**base, "operation_id": "b" * 32, "operation": "revoke", "stage": "session_logout",
                   "endpoint": "revoke", "path": "/realms/fapi-demo/protocol/openid-connect/revoke",
                   "token_kind": "access_token", "http_status": 200},
                  {**base, "operation_id": "c" * 32, "operation": "revoke", "stage": "session_logout",
                   "endpoint": "revoke", "path": "/realms/fapi-demo/protocol/openid-connect/revoke",
                   "token_kind": "refresh_token", "http_status": 200}]
        digest = "A" * 43
        rows = [{
            "v": 1, "observed_at": "2026-10-04T00:00:00Z", "correlation_id": event["operation_id"],
            "endpoint": event["endpoint"], "method": "POST", "path": event["path"].lstrip("/"),
            "peer_present": True, "chain_count": 2, "pkix": True, "valid_now": True,
            "client_auth_eku": True, "leaf_sha256": digest, "error": "none",
        } for event in events]
        receipt = {"route_b_leaf_sha256": digest}
        joined = fixture._join_stock_operations(events, rows, receipt)
        self.assertEqual(joined["operation_join_count"], 3)
        self.assertTrue(all(item["route_b_leaf_matches"] for item in joined["operation_joins"]))
        with self.assertRaisesRegex(fixture.StockFixtureError, "stock_observer_operation_count"):
            fixture._join_stock_operations(events, rows[:-1], receipt)
        with self.assertRaisesRegex(fixture.StockFixtureError, "stock_observer_operation_join_failed"):
            fixture._join_stock_operations(events, [*rows[:-1], {**rows[-1], "pkix": False}], receipt)

    def test_stock_flow_pass_requires_session_callback_cookie_and_logout(self):
        metrics = {
            "ok": True, "outcome": "complete", "http_requests": 6, "redirects": 3,
            "status_2xx": 2, "status_3xx": 3, "status_4xx": 1, "status_5xx": 0,
            "login_submissions": 1, "consent_submissions": 0, "callback_completed": True,
            "callback_http_status": 302, "callback_error_enum": "none",
            "session_cookie_changed": True, "phase_callback_called": True, "logout_completed": True,
        }
        self.assertEqual(fixture._validate_stock_flow_metrics(metrics)["outcome"], "complete")
        diagnosed = {**metrics, "ok": False, "outcome": "callback_rejected", "callback_http_status": 400,
                     "callback_error_enum": "invalid_client", "callback_completed": False,
                     "session_cookie_changed": False, "phase_callback_called": False, "logout_completed": False}
        self.assertEqual(fixture._safe_flow_metrics(diagnosed)["callback_error_enum"], "invalid_client")
        with self.assertRaisesRegex(fixture.StockFixtureError, "stock_flow_not_complete"):
            fixture._validate_stock_flow_metrics(diagnosed)
        with self.assertRaisesRegex(fixture.StockFixtureError, "stock_flow_schema_invalid"):
            fixture._safe_flow_metrics({**metrics, "authorization_code": "should-not-be-present"})

    def test_runtime_log_classifier_keeps_fixed_keycloak_values_and_kong_keyword_presence_only(self):
        raw = b"\n".join((
            b'{"loggerName":"org.keycloak.events","error":"invalid_user_credentials","error_description":"DO_NOT_KEEP"}',
            b"org.keycloak.events ERROR error=invalid_redirect_uri",
            b"org.keycloak.events ERROR error=arbitrary_secret_error_value",
            b"openid-connect token endpoint failure missing token raw=DO_NOT_KEEP, client: code state nonce",
            b"openid-connect authorization_code_verifier invalid_signature failed raw=DO_NOT_KEEP, client: client state",
            b"openid-connect failure raw=DO_NOT_KEEP",
            b"unrelated component error=invalid_client_credentials",
        ))
        diagnostic = fixture._safe_runtime_log_diagnostics(raw)
        self.assertEqual(diagnostic["keycloak_error_counts"]["invalid_user_credentials"], 1)
        self.assertEqual(diagnostic["keycloak_error_counts"]["invalid_redirect_uri"], 1)
        self.assertEqual(diagnostic["keycloak_error_counts"]["unknown"], 1)
        self.assertEqual(diagnostic["keycloak_error_counts"]["invalid_client_credentials"], 0)
        self.assertEqual(diagnostic["kong_oidc_error_counts"]["token_endpoint_failure"], 1)
        self.assertEqual(diagnostic["kong_oidc_error_counts"]["authorization_code_failure"], 1)
        self.assertEqual(diagnostic["kong_oidc_error_counts"]["other_oidc_error"], 1)
        keyword_presence = diagnostic["kong_oidc_keyword_presence"]
        for name in ("token", "missing", "code", "verifier", "signature"):
            self.assertTrue(keyword_presence[name])
        for name in ("nonce", "state", "client"):
            self.assertFalse(keyword_presence[name])
        encoded = json.dumps(diagnostic)
        for sensitive in ("DO_NOT_KEEP", "arbitrary_secret_error_value"):
            self.assertNotIn(sensitive, encoded)

    def test_runtime_log_classifier_rejects_unbounded_input_and_does_not_match_error_description(self):
        diagnostic = fixture._safe_runtime_log_diagnostics(b'{"error_description":"invalid_client"}')
        self.assertEqual(sum(diagnostic["keycloak_error_counts"].values()), 0)
        token_row = {
            "v": 1, "ssl_client_cert_present": True, "ssl_client_priv_key_present": True,
            "client_assertion_present": True, "client_assertion_type_present": True,
            "response_status": 401, "oauth_error_enum": "invalid_client",
            "error_description_keyword_presence": {name: False for name in fixture.KONG_OIDC_KEYWORDS},
        }
        marker_line = (b"raw-request-prefix-secret " + fixture.STOCK_TOKEN_MARKER
                       + json.dumps(token_row, separators=(",", ":")).encode()
                       + b", context: ngx.timer")
        parsed = fixture._parse_stock_token_diagnostic(marker_line)
        self.assertEqual(parsed, token_row)
        self.assertNotIn("raw-request-prefix-secret", json.dumps(parsed))
        with self.assertRaisesRegex(fixture.StockFixtureError, "stock_token_diagnostic_schema_invalid"):
            fixture._parse_stock_token_diagnostic(
                fixture.STOCK_TOKEN_MARKER + json.dumps({**token_row, "response_body": "secret"}).encode()
            )
        with self.assertRaisesRegex(fixture.StockFixtureError, "runtime_log_diagnostic_input_invalid"):
            fixture._safe_runtime_log_diagnostics(b"x" * (fixture.MAX_OUTPUT + 1))

    def test_start_request_preserves_single_redirect_and_bounded_cookies_in_memory(self):
        headers = fixture.http.client.HTTPMessage()
        headers.add_header("Location", "https://localhost:8444/realms/fapi-demo/protocol/openid-connect/auth?request_uri=memory")
        headers.add_header("Set-Cookie", "wp5_stock_route_b_session=fresh; Path=/; Secure; HttpOnly")
        with mock.patch.object(fixture, "_tls_http", return_value=(302, b"", headers)) as request:
            status, location, cookies, body = fixture._start_request(Path("/private/tmp/fake"), time.monotonic() + 3)
        self.assertEqual(status, 302)
        self.assertIn("request_uri=memory", location)
        self.assertEqual(cookies, ["wp5_stock_route_b_session=fresh; Path=/; Secure; HttpOnly"])
        self.assertEqual(body, b"")
        self.assertEqual(request.call_args.args[1:3], (8443, "localhost"))

    def test_runner_never_starts_browser_flow_when_par_peer_join_fails(self):
        root, prep_path, _receipt = self._prepared()
        intent_path = root.parent / f".{root.name}-v15-intent.json"
        run_path = root.parent / f".{root.name}-v15-run.json"
        self.addCleanup(lambda: intent_path.unlink(missing_ok=True))
        self.addCleanup(lambda: run_path.unlink(missing_ok=True))
        event = {
            "operation_id": "a" * 32, "operation": "par", "stage": "par_claim_gate",
            "endpoint": "par", "method": "POST", "path": fixture.PAR_PATH,
            "algorithm": "PS256", "audience_is_issuer": True, "issuer_subject_match": True,
            "ttl_seconds": 60, "remaining_ttl_seconds": 55, "jti_distinct": True,
            "token_kind": "not_applicable", "relay_attempted": True, "forwarded": True,
            "token_distinct": True, "http_status": 201, "oauth_error_enum": "none",
            "stock_form_client_id_present": False, "result": "as_accepted",
        }
        snapshot = {"stage": "par_complete", "failed": False, "overflow": False, "events": [event]}
        patches = {
            "FIXTURE_ROOT": root, "PREP_RECEIPT": prep_path,
            "RUN_INTENT": intent_path, "RUN_RECEIPT": run_path,
        }
        with mock.patch.multiple(fixture, **patches), \
             mock.patch.object(fixture, "preflight_absent"), \
             mock.patch.object(fixture, "_compose", return_value=b""), \
             mock.patch.object(fixture, "_wait_tls"), \
             mock.patch.object(fixture, "_verify_kong_hostgateway_route"), \
             mock.patch.object(fixture, "_start_request", return_value=(302, "https://localhost:8444/realms/fapi-demo/protocol/openid-connect/auth?request_uri=memory", [], b"")), \
             mock.patch.object(fixture, "_status_snapshot", return_value=snapshot), \
             mock.patch.object(fixture, "_capture_keycloak_logs", return_value=(b"", [], {}, fixture._safe_runtime_log_diagnostics(b""))), \
             mock.patch.object(fixture, "verify_owned_resources", return_value={"containers": 0, "volume": False, "network": False}), \
             mock.patch.object(fixture, "_ports_released", return_value={str(port): True for port in fixture.HOST_PORTS}), \
             mock.patch.object(fixture, "_remove_fixture", side_effect=lambda path: shutil.rmtree(path) or True) as cleanup, \
             mock.patch.object(fixture.stock_flow, "run_stock_flow") as flow:
            result = fixture.run_stock_par(root, prep_path, intent_path, run_path, approved_single_attempt=True)
        flow.assert_not_called()
        cleanup.assert_called_once_with(root)
        self.assertEqual(result["stage2"], "not_run")
        self.assertNotEqual(result["result"], "pass")
        self.assertTrue(result["cleanup"]["private_fixture_removed"])

    def test_partial_start_failure_is_receipted_and_never_becomes_pass(self):
        root, prep_path, _receipt = self._prepared()
        stem = root.name
        intent_path = root.parent / f".{stem}-intent.json"
        run_path = root.parent / f".{stem}-run.json"
        self.addCleanup(lambda: intent_path.unlink(missing_ok=True))
        self.addCleanup(lambda: run_path.unlink(missing_ok=True))
        patches = {
            "FIXTURE_ROOT": root,
            "PREP_RECEIPT": prep_path,
            "RUN_INTENT": intent_path,
            "RUN_RECEIPT": run_path,
        }
        with mock.patch.multiple(fixture, **patches), \
             mock.patch.object(fixture, "preflight_absent"), \
             mock.patch.object(fixture, "verify_owned_resources", return_value={
                 "containers": 0, "volume": False, "network": False,
             }), \
             mock.patch.object(fixture, "_ports_released", return_value={str(port): True for port in fixture.HOST_PORTS}), \
             mock.patch.object(fixture, "_remove_fixture", side_effect=lambda path: shutil.rmtree(path) or True) as cleanup, \
             mock.patch.object(fixture, "_compose", side_effect=[b"", fixture.StockFixtureError("compose_start_failed")]):
            result = fixture.run_stock_par(root, prep_path, intent_path, run_path,
                                           approved_single_attempt=True)
        cleanup.assert_called_once_with(root)
        self.assertEqual(result["result"], "failed")
        self.assertEqual(result["failure_category"], "compose_start_failed")
        self.assertEqual(result["stage2"], "not_run")
        self.assertTrue(result["cleanup"]["resources_absent"])
        self.assertTrue(result["cleanup"]["private_fixture_removed"])
        self.assertEqual(json.loads(run_path.read_text())["failure_category"], "compose_start_failed")


if __name__ == "__main__":
    unittest.main()
