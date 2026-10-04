#!/usr/bin/env python3
import copy
import importlib.util
import io
import json
import os
import queue
import subprocess
import tempfile
import unittest
import time
from pathlib import Path
from unittest.mock import patch
import urllib.error
import urllib.parse
from email.message import Message
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SYNC_PATH = ROOT / "scripts/sync-keycloak-demo-data.py"
spec = importlib.util.spec_from_file_location("sync_keycloak_demo_data", SYNC_PATH)
sync = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(sync)

START_PATH = ROOT / "tests/harness/start_wp2_preview.py"
start_spec = importlib.util.spec_from_file_location("start_wp2_preview", START_PATH)
start = importlib.util.module_from_spec(start_spec)
assert start_spec.loader is not None
start_spec.loader.exec_module(start)

FLOW_PATH = ROOT / "tests/harness/wp2_flow.py"
flow_spec = importlib.util.spec_from_file_location("wp2_flow", FLOW_PATH)
flow = importlib.util.module_from_spec(flow_spec)
assert flow_spec.loader is not None
flow_spec.loader.exec_module(flow)

REALM_TEMPLATE = json.loads((ROOT / "keycloak/realm-template.json").read_text())
CLIENTS = REALM_TEMPLATE["clients"]
CLIENT_BY_ID = {client["clientId"]: client for client in CLIENTS}


def live_client(client, client_uuid):
    return {"id": client_uuid, **sync.client_admin_payload(client)}


class WP2SyncPlanTests(unittest.TestCase):
    def test_create_plan_is_additive_and_uses_exact_wp2_inventory(self):
        plan = sync.plan_client_sync(CLIENTS, {client_id: [] for client_id in sync.CLIENT_IDS})
        self.assertEqual({action["operation"] for action in plan}, {"create"})
        self.assertEqual({action["client_id"] for action in plan}, sync.CLIENT_IDS)
        for action in plan:
            self.assertNotIn("secret", action["payload"])
            self.assertNotIn("protocolMappers", action["payload"])
        with self.assertRaisesRegex(RuntimeError, "inventory"):
            sync.plan_client_sync(CLIENTS[:-1], {client_id: [] for client_id in sync.CLIENT_IDS})
        with self.assertRaisesRegex(RuntimeError, "inventory"):
            sync.plan_client_sync([CLIENTS[0], CLIENTS[0], CLIENTS[2]], {client_id: [] for client_id in sync.CLIENT_IDS})

    def test_exact_client_state_is_noop_and_preserves_extra_attributes(self):
        current = {
            client_id: [live_client(client, f"uuid-{client_id}")]
            for client_id, client in CLIENT_BY_ID.items()
        }
        current["third-party-fapi-mtls"][0]["attributes"]["locally-managed-note"] = "preserve"
        plan = sync.plan_client_sync(CLIENTS, current)
        self.assertEqual({action["operation"] for action in plan}, {"noop"})
        self.assertEqual(
            current["third-party-fapi-mtls"][0]["attributes"]["locally-managed-note"],
            "preserve",
        )

    def test_duplicate_live_clients_fail_before_any_plan_can_apply(self):
        matches = {client_id: [] for client_id in sync.CLIENT_IDS}
        target = "third-party-fapi-mtls"
        matches[target] = [
            live_client(CLIENT_BY_ID[target], "uuid-one"),
            live_client(CLIENT_BY_ID[target], "uuid-two"),
        ]
        with self.assertRaisesRegex(RuntimeError, "duplicate Keycloak clients"):
            sync.plan_client_sync(CLIENTS, matches)

    def test_updates_only_allowlisted_client_and_mapper_fields(self):
        current = {
            client_id: [live_client(client, f"uuid-{client_id}")]
            for client_id, client in CLIENT_BY_ID.items()
        }
        route_a = current["third-party-fapi-mtls"][0]
        route_a["attributes"]["local-extension"] = "preserve"
        route_a["enabled"] = False
        plan = sync.plan_client_sync(CLIENTS, current)
        update = next(action for action in plan if action["client_id"] == "third-party-fapi-mtls")
        self.assertEqual(update["operation"], "update")
        update["mapper_plan"] = []
        with patch.object(sync, "request") as request:
            sync.apply_client_sync([update], None, None)
        body = request.call_args.kwargs["body"]
        self.assertEqual(set(body), set(sync.CLIENT_ADMIN_FIELDS) | {"id"})
        self.assertEqual(body["id"], "uuid-third-party-fapi-mtls")
        self.assertEqual(body["attributes"]["local-extension"], "preserve")
        self.assertNotIn("protocolMappers", body)
        self.assertNotIn("clientSecret", body)

        desired_mappers = CLIENT_BY_ID["third-party-fapi-mtls"]["protocolMappers"]
        live_mappers = [
            {"id": f"mapper-{index}", **sync.mapper_admin_payload(mapper)}
            for index, mapper in enumerate(desired_mappers)
        ]
        self.assertEqual(sync.plan_mapper_sync(desired_mappers, live_mappers), [])
        changed = copy.deepcopy(live_mappers)
        changed[0]["config"]["access.token.claim"] = "false"
        mapper_plan = sync.plan_mapper_sync(desired_mappers, changed)
        self.assertEqual(len(mapper_plan), 1)
        self.assertEqual(mapper_plan[0]["operation"], "update")
        self.assertEqual(set(mapper_plan[0]["payload"]), set(sync.MAPPER_ADMIN_FIELDS))

    def test_route_mappers_declare_keycloak_effective_userinfo_defaults_for_full_sync(self):
        for client_id in ("third-party-fapi-mtls", "third-party-fapi-pkj-mtls"):
            desired = CLIENT_BY_ID[client_id]["protocolMappers"]
            live = []
            for index, mapper in enumerate(desired):
                config = mapper["config"]
                with self.subTest(client=client_id, mapper=mapper["name"]):
                    self.assertEqual(config["userinfo.token.claim"], config["id.token.claim"])
                    self.assertEqual(config["introspection.token.claim"], config["access.token.claim"])
                live.append({"id": f"{client_id}-{index}", **sync.mapper_admin_payload(mapper)})
            self.assertEqual(sync.plan_mapper_sync(desired, live), [])

    def test_legacy_clients_are_never_deleted_or_included_in_updates(self):
        current = {client_id: [] for client_id in sync.CLIENT_IDS}
        current["kong-fapi-mtls"] = [{"id": "legacy-a", "clientId": "kong-fapi-mtls"}]
        current["kong-fapi-pkj-mtls"] = [{"id": "legacy-b", "clientId": "kong-fapi-pkj-mtls"}]
        plan = sync.plan_client_sync(CLIENTS, current)
        self.assertEqual(len(plan), 3)
        self.assertTrue(all(action["operation"] == "create" for action in plan))
        self.assertFalse(any("delete" in action["operation"] for action in plan))

    def test_realm_payload_is_partial_and_preserves_unknown_named_entries(self):
        desired = {key: copy.deepcopy(REALM_TEMPLATE[key]) for key in sync.REALM_ADMIN_FIELDS}
        current = copy.deepcopy(desired)
        current["unmanagedRootField"] = "do-not-echo"
        current["clientPolicies"]["unknownGroupField"] = "preserve"
        current["clientPolicies"]["policies"].append({"name": "operator-policy", "enabled": False})
        current["clientPolicies"]["policies"][0]["operatorNote"] = "preserve"
        current["clientProfiles"]["profiles"].append({"name": "operator-profile", "executors": []})
        desired["revokeRefreshToken"] = False
        desired["clientPolicies"]["policies"][0]["enabled"] = False

        payload = sync.realm_admin_payload(current, desired)
        self.assertEqual(set(payload), {"revokeRefreshToken", "clientPolicies"})
        self.assertNotIn("unmanagedRootField", payload)
        policies = payload["clientPolicies"]["policies"]
        self.assertEqual({entry["name"] for entry in policies}, {"fapi-2-confidential-clients", "operator-policy"})
        managed = next(entry for entry in policies if entry["name"] == "fapi-2-confidential-clients")
        self.assertFalse(managed["enabled"])
        self.assertEqual(managed["operatorNote"], "preserve")
        self.assertEqual(payload["clientPolicies"]["unknownGroupField"], "preserve")
        self.assertNotIn("clientProfiles", payload)
        self.assertEqual(
            {entry["name"] for entry in current["clientProfiles"]["profiles"]},
            {"operator-profile"},
        )

    def test_realm_noop_and_duplicate_policy_rejection(self):
        desired = {key: copy.deepcopy(REALM_TEMPLATE[key]) for key in sync.REALM_ADMIN_FIELDS}
        self.assertEqual(sync.realm_admin_payload(desired, desired), {})
        duplicate = copy.deepcopy(desired)
        duplicate["clientPolicies"]["policies"].append(copy.deepcopy(duplicate["clientPolicies"]["policies"][0]))
        with self.assertRaisesRegex(RuntimeError, "duplicate Keycloak client policy"):
            sync.realm_admin_payload(duplicate, desired)


class RedirectSafetyTests(unittest.TestCase):
    def test_admin_bearer_token_is_not_forwarded_on_redirect_and_body_is_suppressed(self):
        received = []
        body = b"redirect-body-secret-sentinel"
        headers = Message()
        headers["Location"] = "https://external.example/admin"

        class FakeOpener:
            def __init__(self, redirect_handler):
                self.redirect_handler = redirect_handler

            def open(self, request, timeout):
                received.append((request.full_url, request.get_header("Authorization"), timeout))
                redirected = self.redirect_handler.redirect_request(
                    request,
                    io.BytesIO(body),
                    302,
                    "Found",
                    headers,
                    headers["Location"],
                )
                self_redirect = redirected
                if self_redirect is not None:
                    received.append((self_redirect.full_url, self_redirect.get_header("Authorization"), timeout))
                raise urllib.error.HTTPError(
                    request.full_url,
                    302,
                    "Found",
                    headers,
                    io.BytesIO(body),
                )

        def make_opener(*handlers):
            redirect_handler = next(handler for handler in handlers if isinstance(handler, sync.NoRedirectHandler))
            return FakeOpener(redirect_handler)

        with patch.object(sync, "BASE_URL", "https://admin.example"), patch.object(
            sync.urllib.request, "build_opener", side_effect=make_opener
        ):
            with self.assertRaisesRegex(RuntimeError, "HTTP 302") as raised:
                sync.request("/admin", None, token="admin-bearer-sentinel")
        self.assertNotIn("redirect-body-secret-sentinel", str(raised.exception))
        self.assertEqual(
            received,
            [("https://admin.example/admin", "Bearer admin-bearer-sentinel", 10)],
        )


class RealmRenderTests(unittest.TestCase):
    def render(self, directory, rotation=None):
        output = Path(directory) / "realm.json"
        public_key = Path(directory) / "route-b.pub"
        public_key.write_text("fixture public key\n")
        environment = {
            **os.environ,
            "SALES_PASSWORD": "temporary-sales-fixture",
            "ENGINEERING_PASSWORD": "temporary-engineering-fixture",
            "DECK_ROUTE_B_JWK_KID": "temporary-route-b-fixture-kid",
        }
        if rotation is not None:
            environment["KEYCLOAK_REFRESH_TOKEN_ROTATION"] = rotation
        else:
            environment.pop("KEYCLOAK_REFRESH_TOKEN_ROTATION", None)
        result = subprocess.run(
            [
                "python3",
                str(ROOT / "scripts/render-keycloak-realm.py"),
                str(ROOT / "keycloak/realm-template.json"),
                str(output),
                str(public_key),
            ],
            env=environment,
            capture_output=True,
            text=True,
        )
        return output, result

    def test_refresh_rotation_is_explicitly_switchable_and_defaults_on(self):
        with tempfile.TemporaryDirectory() as temporary:
            output, result = self.render(temporary)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())["revokeRefreshToken"], True)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

            output_false, result_false = self.render(temporary, "false")
            self.assertEqual(result_false.returncode, 0, result_false.stderr)
            self.assertIs(json.loads(output_false.read_text())["revokeRefreshToken"], False)

            _, invalid = self.render(temporary, "sometimes")
            self.assertNotEqual(invalid.returncode, 0)
            self.assertNotIn("temporary-sales-fixture", invalid.stderr)


class IsolatedPreviewStartTests(unittest.TestCase):
    def run_start(self, docker_results):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        preview = root / ".generated/wp2-preview"
        for relative in (
            "bootstrap.env",
            "realm-import/fapi-demo-realm.json",
            "pki/ca.crt",
            "pki/keycloak.crt",
            "pki/keycloak.key",
        ):
            path = preview / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture")
        calls = []

        def fake_run(command):
            calls.append(command)
            result = docker_results.pop(0)
            return SimpleNamespace(**result)

        with patch.object(start, "ROOT", root), patch.object(start, "PREVIEW", preview), patch.object(
            start, "COMPOSE_FILE", root / "tests/harness/docker-compose.wp2.yml"
        ), patch.object(start, "run", side_effect=fake_run), patch.object(
            start.subprocess, "run", return_value=SimpleNamespace(returncode=0)
        ) as compose_run, patch("sys.argv", ["start_wp2_preview.py", "--allow-start-isolated-keycloak"]), patch(
            "builtins.print"
        ):
            code = start.main()
        return code, calls, compose_run

    def test_volume_lookup_failure_stops_before_compose_up(self):
        code, calls, compose_run = self.run_start([
            {"returncode": 0, "stdout": "26.7.4\n"},
            {"returncode": 0, "stdout": ""},
            {"returncode": 2, "stdout": ""},
        ])
        self.assertEqual(code, 1)
        self.assertFalse(compose_run.called)
        self.assertEqual(calls[-1][0:3], ["docker", "volume", "ls"])

    def test_existing_exact_volume_stops_before_compose_up(self):
        code, _, compose_run = self.run_start([
            {"returncode": 0, "stdout": "26.7.4\n"},
            {"returncode": 0, "stdout": ""},
            {"returncode": 0, "stdout": "other-volume\nwp2-isolated-keycloak-data\n"},
        ])
        self.assertEqual(code, 1)
        self.assertFalse(compose_run.called)

    def test_absent_volume_starts_only_pinned_service_without_build(self):
        code, calls, compose_run = self.run_start([
            {"returncode": 0, "stdout": "26.7.4\n"},
            {"returncode": 0, "stdout": ""},
            {"returncode": 0, "stdout": "wp2-isolated-keycloak-data-other\n"},
        ])
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 3)
        command = compose_run.call_args.args[0]
        self.assertIn("--no-build", command)
        self.assertEqual(command[-4:], ["up", "--no-build", "-d", "keycloak"])


class IsolatedHarnessTests(unittest.TestCase):
    def test_keycloak_url_is_fixed_to_the_isolated_loopback_origin(self):
        self.assertEqual(flow.require_loopback_url("https://localhost:18444"), "https://localhost:18444")
        for value in (
            "https://localhost:8444",
            "https://127.0.0.1:18444",
            "http://localhost:18444",
            "https://localhost:18444/realms/fapi-demo",
            "https://user@localhost:18444",
        ):
            with self.subTest(value=value), self.assertRaises(flow.ProbeError):
                flow.require_loopback_url(value)

    def test_authorization_callback_must_match_state_and_registered_path(self):
        callback_server = object.__new__(flow.CallbackServer)
        callback_server.server = SimpleNamespace(callback_queue=queue.Queue())
        callback_server.server.callback_queue.put({
            "path": "/api/fapi/mtls",
            "code": "memory-only-code",
            "state": "expected-state",
            "error": None,
            "received_at": time.time(),
        })
        with self.assertRaisesRegex(flow.ProbeError, "callback path"):
            callback_server.receive("expected-state", "/api/fapi/pkj-mtls")

        callback_server.server.callback_queue.put({
            "path": "/api/fapi/mtls",
            "code": "memory-only-code",
            "state": "expected-state",
            "error": None,
            "received_at": time.time(),
        })
        received = callback_server.receive("expected-state", "/api/fapi/mtls")
        self.assertEqual(received["path"], "/api/fapi/mtls")

    def test_audience_mapper_guard_accepts_declared_userinfo_default_and_keeps_other_drift_strict(self):
        client_id = "third-party-fapi-mtls"
        desired_client = CLIENT_BY_ID[client_id]
        desired_mapper = next(
            mapper for mapper in desired_client["protocolMappers"]
            if mapper["name"] == "api-gateway-introspection-audience"
        )
        client_path = "/admin/realms/fapi-demo/clients?clientId=" + client_id
        mapper_path = "/admin/realms/fapi-demo/clients/client-uuid/protocol-mappers/models"
        baseline = copy.deepcopy(desired_mapper["config"])
        calls = []
        is_updated = False
        changed = copy.deepcopy(baseline)
        changed["access.token.claim"] = "false"

        def fake_request(_base, path, _ca, **kwargs):
            nonlocal is_updated
            calls.append((path, kwargs))
            if path == client_path:
                return [{"id": "client-uuid"}]
            if kwargs.get("method") == "PUT":
                self.assertEqual(kwargs["json_body"]["config"], changed)
                is_updated = True
                return {}
            if path == mapper_path:
                config = changed if is_updated else baseline
                return [{"id": "mapper-uuid", "name": desired_mapper["name"], "config": config}]
            return [{"id": "mapper-uuid", "name": desired_mapper["name"], "config": changed}]

        with patch.object(flow, "request_json", side_effect=fake_request):
            flow.change_audience_mapper(
                "https://localhost:18444", Path("/unused"), "memory-only-admin-token", "a", False
            )
        self.assertEqual([kwargs.get("method", "GET") for _, kwargs in calls], ["GET", "GET", "PUT", "GET"])

        for drift in (
            {**baseline, "unexpected.key": "true"},
            {**baseline, "userinfo.token.claim": "true"},
        ):
            preflight_calls = []

            def drift_request(_base, path, _ca, **kwargs):
                preflight_calls.append(path)
                if path == client_path:
                    return [{"id": "client-uuid"}]
                return [{"id": "mapper-uuid", "name": desired_mapper["name"], "config": drift}]

            with patch.object(flow, "request_json", side_effect=drift_request):
                with self.assertRaisesRegex(flow.ProbeError, "unexpected unmanaged drift"):
                    flow.change_audience_mapper(
                        "https://localhost:18444", Path("/unused"), "memory-only-admin-token", "a", False
                    )
            self.assertEqual(len(preflight_calls), 2, "unexpected mapper drift stops before any update")

    def test_user_profile_sync_merges_managed_attributes_and_preserves_unknowns(self):
        desired = json.loads((ROOT / "keycloak/user-profile.json").read_text())
        live = {
            "attributes": [
                {"name": "custom-operator-attribute", "displayName": "Operator"},
                {"name": "department", "displayName": "Old department"},
            ],
            "unmanagedProfileSetting": {"preserve": True},
        }
        updated = {**live, "attributes": [live["attributes"][0], *desired["attributes"]]}
        calls = []

        def fake_request(_base, _path, _ca, **kwargs):
            calls.append(kwargs)
            if kwargs.get("method") == "PUT":
                self.assertEqual(kwargs["json_body"]["unmanagedProfileSetting"], {"preserve": True})
                return {}
            return live if len(calls) == 1 else updated

        with patch.object(flow, "request_json", side_effect=fake_request):
            flow.sync_user_profile("https://localhost:18444", Path("/unused"), "admin-token")
        self.assertEqual([call.get("method", "GET") for call in calls], ["GET", "PUT", "GET"])
        final_attributes = calls[1]["json_body"]["attributes"]
        names = [item["name"] for item in final_attributes]
        self.assertIn("custom-operator-attribute", names)
        self.assertEqual(set(names), {"custom-operator-attribute", "department", "departement", "route"})

    def test_fixture_user_attribute_sync_restores_missing_custom_attributes_and_preserves_unknowns(self):
        desired_users = json.loads((ROOT / "keycloak/realm-template.json").read_text())["users"]
        current = {
            desired_users[0]["username"]: {
                "username": desired_users[0]["username"],
                "id": "fixture-sales-id",
                "attributes": {"operatorTag": ["keep-sales"], "department": ["stale"]},
            },
            desired_users[1]["username"]: {
                "username": desired_users[1]["username"],
                "id": "fixture-engineering-id",
                "attributes": {"operatorTag": ["keep-engineering"], "departement": ["engineering"]},
            },
        }
        paths = []
        writes = []

        def fake_request(_base, path, _ca, **kwargs):
            paths.append(path)
            parsed = urllib.parse.urlsplit(path)
            if kwargs.get("method") == "PUT":
                body = kwargs["json_body"]
                self.assertEqual(set(body), {"id", "attributes"})
                target = next(user for user in current.values() if user["id"] == body["id"])
                target["attributes"] = copy.deepcopy(body["attributes"])
                writes.append((path, copy.deepcopy(body)))
                return {}
            if parsed.query:
                query = urllib.parse.parse_qs(parsed.query)
                username = query["username"][0]
                self.assertEqual(query["exact"], ["true"])
                return [{"id": current[username]["id"], "username": username}]
            user_id = parsed.path.rsplit("/", 1)[1]
            return copy.deepcopy(next(user for user in current.values() if user["id"] == user_id))

        with patch.object(flow, "request_json", side_effect=fake_request):
            flow.sync_fixture_user_attributes("https://localhost:18444", Path("/unused"), "memory-only-admin-token")

        self.assertEqual(len(writes), 2)
        for desired_user in desired_users:
            attributes = current[desired_user["username"]]["attributes"]
            for name, value in desired_user["attributes"].items():
                self.assertEqual(attributes[name], value)
            self.assertEqual(attributes["operatorTag"][0], "keep-" + desired_user["attributes"]["department"][0])
        self.assertEqual(len([path for path in paths if path.startswith("/admin/realms/fapi-demo/users?")]), 2)
        self.assertEqual(len([path for path in paths if path.startswith("/admin/realms/fapi-demo/users/")]), 6)

    def test_fixture_user_duplicate_lookup_stops_before_any_user_update(self):
        calls = []

        def fake_request(_base, path, _ca, **kwargs):
            calls.append((path, kwargs.get("method", "GET")))
            return [{"id": "one"}, {"id": "two"}]

        with patch.object(flow, "request_json", side_effect=fake_request):
            with self.assertRaisesRegex(flow.ProbeError, "exactly one user"):
                flow.sync_fixture_user_attributes(
                    "https://localhost:18444", Path("/unused"), "memory-only-admin-token"
                )
        self.assertEqual(len(calls), 1)
        self.assertFalse(any(method == "PUT" for _, method in calls))

    def test_fixture_user_id_mismatch_stops_before_detail_read_or_update(self):
        calls = []

        def fake_request(_base, path, _ca, **kwargs):
            calls.append((path, kwargs.get("method", "GET")))
            return [{"id": "one", "username": "different-user"}]

        with patch.object(flow, "request_json", side_effect=fake_request):
            with self.assertRaisesRegex(flow.ProbeError, "different user"):
                flow.sync_fixture_user_attributes(
                    "https://localhost:18444", Path("/unused"), "memory-only-admin-token"
                )
        self.assertEqual(len(calls), 1)
        self.assertFalse(any(method == "PUT" for _, method in calls))

    def test_protocol_error_exposes_only_known_oauth_error_codes(self):
        class FakeOpener:
            def __init__(self, response_body):
                self.response_body = response_body

            def open(self, request, timeout):
                raise urllib.error.HTTPError(
                    request.full_url,
                    400,
                    "Bad Request",
                    Message(),
                    io.BytesIO(self.response_body),
                )

        secret_body = json.dumps({
            "error": "opaque-assertion-jti-secret",
            "error_description": "raw-error-description-secret",
        }).encode()
        with patch.object(flow, "ssl_context", return_value=object()), patch.object(
            flow.urllib.request, "build_opener", return_value=FakeOpener(secret_body)
        ):
            with self.assertRaises(flow.ProtocolResponseError) as raised:
                flow.request_json("https://localhost:18444", "/token", Path("/unused"))
        self.assertIsNone(raised.exception.error_code)
        self.assertIsNone(raised.exception.error_reason)
        self.assertNotIn("opaque-assertion-jti-secret", str(raised.exception))
        self.assertNotIn("raw-error-description-secret", str(raised.exception))

        known_body = json.dumps({"error": "invalid_request", "error_description": "secret"}).encode()
        with patch.object(flow, "ssl_context", return_value=object()), patch.object(
            flow.urllib.request, "build_opener", return_value=FakeOpener(known_body)
        ):
            with self.assertRaises(flow.ProtocolResponseError) as raised_known:
                flow.request_json("https://localhost:18444", "/token", Path("/unused"))
        self.assertEqual(raised_known.exception.error_code, "invalid_request")
        self.assertIsNone(raised_known.exception.error_reason)

        for description, expected_reason in (
            ("invalid audience in client assertion", "client_assertion_audience"),
            ("Client Certification missing for MTLS HoK Token Binding", "mtls_client_certificate_missing"),
        ):
            source_error = json.dumps({
                "error": "invalid_grant",
                "error_description": description,
            }).encode()
            with patch.object(flow, "ssl_context", return_value=object()), patch.object(
                flow.urllib.request, "build_opener", return_value=FakeOpener(source_error)
            ):
                with self.assertRaises(flow.ProtocolResponseError) as source_raised:
                    flow.request_json("https://localhost:18444", "/token", Path("/unused"))
            self.assertEqual(source_raised.exception.error_code, "invalid_grant")
            self.assertEqual(source_raised.exception.error_reason, expected_reason)
            self.assertNotIn(description, str(source_raised.exception))

        wrong_outer_code = json.dumps({
            "error": "invalid_request",
            "error_description": "invalid audience in client assertion",
        }).encode()
        with patch.object(flow, "ssl_context", return_value=object()), patch.object(
            flow.urllib.request, "build_opener", return_value=FakeOpener(wrong_outer_code)
        ):
            with self.assertRaises(flow.ProtocolResponseError) as outer_raised:
                flow.request_json("https://localhost:18444", "/token", Path("/unused"))
        self.assertEqual(outer_raised.exception.error_code, "invalid_request")
        self.assertIsNone(outer_raised.exception.error_reason)

        unknown_reason = flow.ProtocolResponseError(400, "invalid_grant", "opaque-private-error-detail")
        self.assertIsNone(unknown_reason.error_reason)
        self.assertNotIn("opaque-private-error-detail", str(unknown_reason))
        self.assertIsNone(flow.case_result(
            "B-AUD-01", "b", "fail", "AS", 400, "invalid_grant",
            error_reason="opaque-private-error-detail",
        )["oauth_reason"])

    def test_policy_wrapped_invalid_grant_passes_only_with_exact_sanitized_reason(self):
        cases = (
            ("B-AUD-01", "client_assertion_audience"),
            ("B-CERT-01", "mtls_client_certificate_missing"),
        )
        for case_id, reason in cases:
            with self.subTest(case_id=case_id), patch.object(
                flow,
                "exchange_code",
                side_effect=flow.ProtocolResponseError(400, "invalid_grant", reason),
            ), patch("builtins.print"):
                result = flow.expect_as_rejection(
                    case_id,
                    "b",
                    {},
                    "https://localhost:18444/realms/fapi-demo",
                    {},
                    Path("/unused"),
                    Path("/unused"),
                )
            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["oauth_error"], "invalid_grant")
            self.assertEqual(result["oauth_reason"], reason)

        for case_id, error_code, reason in (
            ("B-AUD-01", "invalid_grant", None),
            ("B-AUD-01", "invalid_request", "client_assertion_audience"),
            ("B-CERT-01", "invalid_grant", None),
            ("B-CERT-01", "invalid_grant", "client_assertion_audience"),
        ):
            with self.subTest(case_id=case_id, error_code=error_code, reason=reason), patch.object(
                flow,
                "exchange_code",
                side_effect=flow.ProtocolResponseError(400, error_code, reason),
            ), patch("builtins.print"):
                result = flow.expect_as_rejection(
                    case_id,
                    "b",
                    {},
                    "https://localhost:18444/realms/fapi-demo",
                    {},
                    Path("/unused"),
                    Path("/unused"),
                )
            self.assertEqual(result["status"], "fail")

        for case_id, reason in cases:
            with self.subTest(case_id=case_id, status=401), patch.object(
                flow,
                "exchange_code",
                side_effect=flow.ProtocolResponseError(401, "invalid_grant", reason),
            ), patch("builtins.print"):
                result = flow.expect_as_rejection(
                    case_id,
                    "b",
                    {},
                    "https://localhost:18444/realms/fapi-demo",
                    {},
                    Path("/unused"),
                    Path("/unused"),
                )
            self.assertEqual(result["status"], "fail")

    def test_b_cert_rejects_invalid_client_and_jti_rejects_invalid_grant_as_false_positives(self):
        for case_id, error_code in (("B-CERT-01", "invalid_client"), ("B-JTI-01", "invalid_grant")):
            with self.subTest(case_id=case_id), patch.object(
                flow,
                "exchange_code",
                side_effect=flow.ProtocolResponseError(400, error_code),
            ), patch("builtins.print"):
                result = flow.expect_as_rejection(
                    case_id,
                    "b",
                    {},
                    "https://localhost:18444/realms/fapi-demo",
                    {},
                    Path("/unused"),
                    Path("/unused"),
                )
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["layer"], "AS")
            self.assertEqual(result["oauth_error"], error_code)

    def test_as_negative_receipt_keeps_completed_case_when_later_grant_setup_fails(self):
        receipt = flow.initial_receipt()
        completed = flow.case_result(
            "A-CERT-01", "a", "pass", "AS", 400, "invalid_client", "expected-AS-rejection"
        )
        with patch.object(
            flow,
            "authorize_code",
            side_effect=[{"grant": "memory-only"}, flow.ProbeError("synthetic local failure")],
        ), patch.object(flow, "expect_as_rejection", return_value=completed):
            with self.assertRaisesRegex(flow.ProbeError, "synthetic"):
                flow.run_as_negatives(
                    "https://localhost:18444",
                    {},
                    "https://localhost:18444/realms/fapi-demo",
                    Path("/unused"),
                    object(),
                    Path("/unused"),
                    {},
                    receipt=receipt,
                )
        observed = {
            (case["case_id"], case["route_client_id"]): case["status"]
            for case in receipt["cases"]
        }
        self.assertEqual(observed[("A-CERT-01", "third-party-fapi-mtls")], "pass")
        self.assertEqual(observed[("A-CERT-02", "third-party-fapi-mtls")], "not_run")

    def test_receipt_contains_only_sanitized_acceptance_fields_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            preview = Path(temporary)
            receipt = flow.initial_receipt()
            flow.update_receipt_case(
                receipt,
                flow.case_result("RS-INT-AUD-02", "a", "pass", "JWT+dedicated-mTLS-introspection", 200),
            )
            flow.write_receipt(preview, receipt)
            path = preview / "evidence/wp2-receipt.json"
            data = path.read_text()
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("token", data.lower().replace("route_client_id", ""))
            parsed = json.loads(data)
            self.assertEqual(
                {case["status"] for case in parsed["cases"] if case["case_id"] != "RS-INT-AUD-02"},
                {"not_run"},
            )
            with self.assertRaisesRegex(flow.ProbeError, "overwrite"):
                flow.write_receipt(preview, receipt)

    @unittest.skipUnless(importlib.util.find_spec("jwt"), "PyJWT crypto dependency is installed in validation environments")
    def test_ps256_verifier_accepts_valid_and_rejects_tampered_or_wrong_algorithm_tokens(self):
        import jwt
        from cryptography.hazmat.primitives import serialization

        with tempfile.TemporaryDirectory() as temporary:
            private_path = Path(temporary) / "signing.key"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        public_key = private_key.public_key()
        issuer = "https://localhost:18444/realms/fapi-demo"
        client_id = "third-party-fapi-pkj-mtls"
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
        jwk["kid"] = "wp2-test-key"
        jwk["alg"] = "PS256"
        jwk["use"] = "sig"
        jwks = {"keys": [jwk]}
        claims = {"iss": issuer, "iat": int(time.time()), "exp": int(time.time()) + 120, "aud": "fapi-demo-api"}
        valid = jwt.encode(claims, private_key, algorithm="PS256", headers={"kid": "wp2-test-key"})
        _header, verified = flow.verify_ps256(valid, jwks, issuer=issuer, audience="fapi-demo-api")
        self.assertEqual(verified["iss"], issuer)

        stale_calls = []
        stale_jwks = flow.JwksDocument(
            {"keys": [{**jwk, "kid": "pre-token-rs256-key", "alg": "RS256"}]},
            refresh=lambda: stale_calls.append(True) or {"keys": [jwk]},
        )
        flow.verify_ps256(valid, stale_jwks, issuer=issuer, audience="fapi-demo-api")
        flow.verify_ps256(valid, stale_jwks, issuer=issuer, audience="fapi-demo-api")
        self.assertEqual(stale_calls, [True], "unknown kid refresh is bounded and cached")
        self.assertEqual(stale_jwks.document, {"keys": [jwk]})

        still_missing_calls = []
        still_missing = flow.JwksDocument(
            {"keys": []},
            refresh=lambda: still_missing_calls.append(True) or {"keys": [{**jwk, "kid": "another-key"}]},
        )
        for _ in range(2):
            with self.assertRaisesRegex(flow.ProbeError, "unique matching PS256"):
                flow.verify_ps256(valid, still_missing, issuer=issuer, audience="fapi-demo-api")
        self.assertEqual(still_missing_calls, [True], "a missing key is refreshed only once per run")

        same_kid_wrong_alg_calls = []
        wrong_jwk_algorithm = flow.JwksDocument(
            {"keys": [{**jwk, "alg": "RS256"}]},
            refresh=lambda: same_kid_wrong_alg_calls.append(True) or {"keys": [jwk]},
        )
        with self.assertRaisesRegex(flow.ProbeError, "PS256"):
            flow.verify_ps256(valid, wrong_jwk_algorithm, issuer=issuer, audience="fapi-demo-api")
        self.assertEqual(same_kid_wrong_alg_calls, [], "a same-kid wrong-alg key is not refreshed or accepted")

        for wrong_metadata in ({"use": "enc"}, {"kty": "EC"}):
            wrong_metadata_calls = []
            wrong_jwk_metadata = flow.JwksDocument(
                {"keys": [{**jwk, **wrong_metadata}]},
                refresh=lambda: wrong_metadata_calls.append(True) or {"keys": [jwk]},
            )
            with self.assertRaisesRegex(flow.ProbeError, "unique matching PS256"):
                flow.verify_ps256(valid, wrong_jwk_metadata, issuer=issuer, audience="fapi-demo-api")
            self.assertEqual(wrong_metadata_calls, [], "same-kid wrong-use/type keys are never refreshed or accepted")

        duplicate_ps256 = flow.JwksDocument({"keys": [jwk, dict(jwk)]})
        with self.assertRaisesRegex(flow.ProbeError, "unique matching PS256"):
            flow.verify_ps256(valid, duplicate_ps256, issuer=issuer, audience="fapi-demo-api")

        same_kid_other_algorithm = flow.JwksDocument({
            "keys": [{**jwk, "alg": "RS256"}, jwk],
        })
        flow.verify_ps256(valid, same_kid_other_algorithm, issuer=issuer, audience="fapi-demo-api")

        parts = valid.split(".")
        tampered_claims = {**claims, "sub": "tampered"}
        tampered_payload = flow.b64url(
            json.dumps(tampered_claims, separators=(",", ":")).encode()
        )
        tampered = f"{parts[0]}.{tampered_payload}.{parts[2]}"
        tampered_calls = []
        known_key = flow.JwksDocument(
            jwks,
            refresh=lambda: tampered_calls.append(True) or {"keys": [jwk]},
        )
        with self.assertRaisesRegex(flow.ProbeError, "PS256"):
            flow.verify_ps256(tampered, known_key, issuer=issuer, audience="fapi-demo-api")
        self.assertEqual(tampered_calls, [], "signature failure with a known kid does not trigger JWKS refresh")

        wrong_algorithm = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "wp2-test-key"})
        with self.assertRaisesRegex(flow.ProbeError, "PS256"):
            flow.verify_ps256(wrong_algorithm, jwks, issuer=issuer, audience="fapi-demo-api")

        with tempfile.TemporaryDirectory() as temporary:
            private_path = Path(temporary) / "route-b-pkj.key"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            public_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None).public_key()
            assertion = flow.sign_client_assertion(client_id, issuer, private_path)
            expected_client_kid = flow.keycloak_key_id(private_path)
        assertion_header = jwt.get_unverified_header(assertion)
        self.assertEqual(assertion_header["alg"], "PS256")
        self.assertEqual(assertion_header["kid"], expected_client_kid)
        assertion_claims = jwt.decode(
            assertion,
            public_key,
            algorithms=["PS256"],
            issuer=client_id,
            audience=issuer,
        )
        self.assertLessEqual(assertion_claims["exp"] - assertion_claims["iat"], 60)


if __name__ == "__main__":
    unittest.main(verbosity=2)
