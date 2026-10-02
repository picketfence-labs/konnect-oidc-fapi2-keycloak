#!/usr/bin/env python3
import copy
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import yaml
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from wp1 import (  # noqa: E402
    ROUTES,
    collect_schema_pages,
    compare_schema_hashes,
    endpoint_host,
    validate_route_manifest,
    validate_selector,
    validate_targets,
)

TARGET_CLI = Path(__file__).resolve().parents[1] / "scripts/wp1_target.py"
spec = importlib.util.spec_from_file_location("wp1_target", TARGET_CLI)
wp1_target = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wp1_target)
RUN_DECK = Path(__file__).resolve().parents[1] / "scripts/run-deck.py"
deck_spec = importlib.util.spec_from_file_location("run_deck", RUN_DECK)
run_deck = importlib.util.module_from_spec(deck_spec)
assert deck_spec.loader is not None
deck_spec.loader.exec_module(run_deck)


def write_cli_fixture(root: Path, source: Path) -> None:
    (root / "infra").mkdir()
    (root / "kong/foundation").mkdir(parents=True)
    (root / ".generated").mkdir()
    for filename in ("api.yaml", "third-party.yaml"):
        (root / "kong/foundation" / filename).write_bytes((source / "kong/foundation" / filename).read_bytes())
    (root / ".env").write_text(
        "KONNECT_TOKEN=token-sentinel\n"
        "TF_VAR_control_plane_name=keycloak-fapi2-demo\n"
        "TF_VAR_third_party_control_plane_name=keycloak-fapi2-third-party-demo\n"
    )
    (root / ".generated/gateway_targets.json").write_text(json.dumps({
        "konnect_server_url": "https://us.api.konghq.com",
        "targets": {
            "api": {"control_plane_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "control_plane_name": "keycloak-fapi2-demo", "control_plane_endpoint": "https://api.cp.konghq.com", "telemetry_endpoint": "https://api.tp.konghq.com"},
            "third-party": {"control_plane_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "control_plane_name": "keycloak-fapi2-third-party-demo", "control_plane_endpoint": "https://third.cp.konghq.com", "telemetry_endpoint": "https://third.tp.konghq.com"},
        },
    }))
    (root / ".generated/runtime-api.json").write_text(json.dumps({"API_INTROSPECTION_KEY": "PRIVATE_SENTINEL"}))
    (root / ".generated/deck.env").write_text("DECK_API_INTROSPECTION_CERT_YAML=PUBLIC_CERT_SENTINEL\n")


class WP1FoundationTests(unittest.TestCase):
    def test_worker_environment_injection_uses_separate_env_directives(self):
        source = Path(__file__).resolve().parents[1]
        services = yaml.safe_load((source / "docker-compose.yml").read_text())["services"]
        expected = {
            "kong-api": {"API_INTROSPECTION_KEY", "API_UPSTREAM_KEY"},
            "kong-third-party": {"ROUTE_A_TLS_KEY", "ROUTE_B_TLS_KEY",
                                 "FAPI_AS_TRANSPORT_ISSUER", "FAPI_AS_TRANSPORT_INTERNAL_ORIGIN"},
        }
        for name, required in expected.items():
            value = services[name]["environment"]["KONG_NGINX_MAIN_ENV"]
            directives = ("env " + value + ";").split(";")[:-1]
            variables = []
            for directive in directives:
                match = re.fullmatch(r"env ([A-Z_]+)", directive.strip())
                self.assertIsNotNone(match, "NGINX env accepts one variable per directive")
                variables.append(match.group(1))
            self.assertEqual(set(variables), required)
            self.assertEqual(len(variables), len(required))

    def test_schema_shell_rejects_stage_and_extra_arguments_before_python(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            marker = temporary / "python-called"
            fake_python = temporary / "python3"
            fake_python.write_text('#!/bin/sh\ntouch "$CALL_MARKER"\nexit 0\n')
            fake_python.chmod(0o700)
            environment = {**os.environ, "PATH": f"{temporary}:{os.environ['PATH']}",
                           "CALL_MARKER": str(marker), "GATEWAY": "third-party"}
            environment.pop("STAGE", None)
            cases = [(["check"], "foundation"), (["check"], ""),
                     (["check", "--stage", "foundation"], None)]
            for arguments, stage in cases:
                scoped = dict(environment)
                if stage is not None:
                    scoped["STAGE"] = stage
                result = subprocess.run([str(source / "scripts/plugin-schema.sh"), *arguments],
                                        env=scoped, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("STAGE is not supported", result.stderr)
                self.assertFalse(marker.exists())

    def setUp(self):
        self.targets = {
            "api": {
                "control_plane_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "control_plane_name": "api-demo",
                "control_plane_endpoint": "https://api.cp.konghq.com",
                "telemetry_endpoint": "https://api.tp.konghq.com",
            },
            "third-party": {
                "control_plane_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "control_plane_name": "third-party-demo",
                "control_plane_endpoint": "https://third.cp.konghq.com",
                "telemetry_endpoint": "https://third.tp.konghq.com",
            },
        }

    def test_selector_accepts_only_supported_operations(self):
        validate_selector("api", "foundation", "diff")
        validate_selector("third-party", None, "schema")
        for gateway, stage, operation in [
            ("api", None, "diff"),
            ("other", "foundation", "sync"),
            ("api", "runtime", "schema"),
            ("third-party", "final", "diff"),
        ]:
            with self.assertRaises(ValueError):
                validate_selector(gateway, stage, operation)

    def test_target_manifest_positive_and_negative(self):
        result = validate_targets(self.targets, {"api": "api-demo", "third-party": "third-party-demo"})
        self.assertEqual(result["third-party"]["telemetry_host"], "third.tp.konghq.com")
        invalid = copy.deepcopy(self.targets)
        invalid["third-party"]["control_plane_id"] = invalid["api"]["control_plane_id"]
        with self.assertRaisesRegex(ValueError, "IDs must differ"):
            validate_targets(invalid)
        invalid = copy.deepcopy(self.targets)
        invalid["api"]["control_plane_id"] = "not-a-uuid"
        with self.assertRaisesRegex(ValueError, "is not a UUID"):
            validate_targets(invalid)
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_targets(self.targets, {"api": "other", "third-party": "third-party-demo"})
        invalid = copy.deepcopy(self.targets)
        invalid["api"]["telemetry_endpoint"] = " https://api.tp.konghq.com"
        with self.assertRaises(ValueError):
            validate_targets(invalid)

    def test_endpoint_rejects_ambiguous_or_unsafe_values(self):
        self.assertEqual(endpoint_host("https://KONG.example:443/"), "kong.example")
        for endpoint in [
            "http://kong.example",
            "https://user@kong.example",
            "https://kong.example/path",
            "https://kong.example?target=bad",
            "https://kong.example:8443",
            "https://kong.example\n.invalid",
            "https://kong.example:bad",
        ]:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                endpoint_host(endpoint)

    def test_fixed_route_manifest(self):
        validate_route_manifest(list(ROUTES))
        swapped = copy.deepcopy(list(ROUTES))
        swapped[0]["client_id"], swapped[1]["client_id"] = swapped[1]["client_id"], swapped[0]["client_id"]
        with self.assertRaisesRegex(ValueError, "fixed A/B"):
            validate_route_manifest(swapped)
        duplicated = [copy.deepcopy(ROUTES[0]), copy.deepcopy(ROUTES[0])]
        with self.assertRaisesRegex(ValueError, "fixed A/B"):
            validate_route_manifest(duplicated)

    def test_generated_third_party_certificate_paths_are_ignored(self):
        root = Path(__file__).resolve().parents[1]
        ignored = subprocess.run(
            ["git", "check-ignore", "--no-index", "infra/certs/third-party/tls.key"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        kept = subprocess.run(
            ["git", "check-ignore", "--no-index", "infra/certs/third-party/.gitkeep"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(ignored.returncode, 0)
        self.assertEqual(kept.returncode, 1)

    def test_schema_inventory_pagination_and_original_lua(self):
        pages = [
            {
                "items": [{"name": "transport", "lua_schema": "return {}\n", "created_at": "2026-01-01", "updated_at": "2026-01-01"}],
                "page": {"total_count": 2, "next_cursor": "opaque-1", "has_next_page": True},
                "request_cursor": None,
            },
            {
                "items": [{"name": "bridge", "lua_schema": "return {}", "created_at": "2026-01-01", "updated_at": "2026-01-01"}],
                "page": {"total_count": 2, "next_cursor": "opaque-last", "has_next_page": False},
                "request_cursor": "opaque-1",
            },
        ]
        observed = collect_schema_pages(pages, {"transport", "bridge"})
        hashes = compare_schema_hashes(
            {"transport": "return {}", "bridge": "return {}\r\n"}, observed
        )
        self.assertEqual(set(hashes), {"transport", "bridge"})
        for invalid in [
            pages[:1],
            [pages[0]],
            [pages[0], {"items": pages[1]["items"], "page": {"total_count": 3, "next_cursor": "last", "has_next_page": False}}],
            [pages[0], {"items": [dict(pages[1]["items"][0], name="transport")], "page": {"total_count": 2, "next_cursor": "last", "has_next_page": False}}],
            [{"items": [{"name": "transport", "lua_schema": ""}], "page": {"total_count": 1, "next_cursor": "last", "has_next_page": False}}],
            [{"items": [{"name": "transport", "lua_schema": "x"}], "page": {"total_count": 1, "next_cursor": "same", "has_next_page": True}, "request_cursor": "same"}],
            [{"items": [], "page": {"total_count": True, "has_next_page": False}}],
        ]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                collect_schema_pages(invalid, {"transport", "bridge"})
        with self.assertRaisesRegex(ValueError, "drift"):
            compare_schema_hashes({"transport": "return {x=1}"}, {"transport": "return {x=2}"})

    def test_schema_cli_uses_opaque_cursor_and_stops_on_has_next_false(self):
        responses = [
            (200, {"items": [{"name": "a", "lua_schema": "a"}], "page": {"total_count": 2, "next_cursor": "opaque-token", "has_next_page": True}}),
            (200, {"items": [{"name": "b", "lua_schema": "b"}], "page": {"total_count": 2, "next_cursor": "opaque-final", "has_next_page": False}}),
        ]
        urls = []

        def request(url, token):
            urls.append(url)
            return responses.pop(0)

        with patch.object(wp1_target, "request_json", side_effect=request):
            pages = wp1_target.request_schema_pages("https://example.test/schemas", "secret")
        self.assertIn("page%5Bafter%5D=opaque-token", urls[1])
        self.assertEqual(len(urls), 2)
        self.assertEqual(pages[-1]["page"]["next_cursor"], "opaque-final")

    def test_schema_cli_rejects_bad_pagination_before_inventory_use(self):
        cases = [
            {"items": [], "page": {"total_count": 1, "next_cursor": "opaque", "has_next_page": False}},
            {"items": [{"name": "a", "lua_schema": "x"}], "page": {"total_count": 1, "next_cursor": "same", "has_next_page": True}},
            {"items": [{"name": "a", "lua_schema": "x"}], "page": {"total_count": 2, "has_next_page": True}},
            {"items": [], "page": {"total_count": True, "has_next_page": False}},
        ]
        for case in cases:
            with self.subTest(case=case), patch.object(wp1_target, "request_json", return_value=(200, case)):
                with self.assertRaises(ValueError):
                    wp1_target.request_schema_pages("https://example.test/schemas", "secret")

        repeated = [
            (200, {"items": [{"name": "a", "lua_schema": "a"}], "page": {"total_count": 3, "next_cursor": "opaque", "has_next_page": True}}),
            (200, {"items": [{"name": "b", "lua_schema": "b"}], "page": {"total_count": 3, "next_cursor": "opaque", "has_next_page": True}}),
        ]
        with patch.object(wp1_target, "request_json", side_effect=repeated):
            with self.assertRaisesRegex(ValueError, "cursor"):
                wp1_target.request_schema_pages("https://example.test/schemas", "secret")

        empty = {"items": [], "page": {"total_count": 0, "has_next_page": False}}
        with patch.object(wp1_target, "request_json", return_value=(200, empty)):
            pages = wp1_target.request_schema_pages("https://example.test/schemas", "secret")
        self.assertEqual(pages[0]["items"], [])
        with patch.object(wp1_target, "request_json", return_value=(404, empty)):
            with self.assertRaisesRegex(ValueError, "HTTP 404"):
                wp1_target.request_schema_pages("https://example.test/schemas", "secret")

    def test_schema_sync_validates_full_inventory_before_any_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for path in wp1_target.PLUGIN_FILES.values():
                destination = root / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("return { fields = {} }\n")
            target = {"control_plane_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
            empty = {"items": [], "page": {"total_count": 0, "next_cursor": None, "has_next_page": False}}
            writes = []

            def request(url, token, *, method="GET", body=None):
                if method == "GET":
                    return 200, empty
                writes.append((method, url, body))
                return 201, {}

            with patch.object(wp1_target, "request_json", side_effect=request):
                wp1_target.sync_schemas(root, "https://us.api.konghq.com", target, "token")
            self.assertEqual([write[0] for write in writes], ["POST", "POST"])

            malformed_rows = [
                [{"name": None, "lua_schema": "return {}"}],
                [{"name": "bridge", "lua_schema": None}],
                [{"name": "bridge", "lua_schema": "return {}"}, {"name": "bridge", "lua_schema": "return {}"}],
            ]
            for rows in malformed_rows:
                writes.clear()
                response = {"items": rows, "page": {"total_count": len(rows), "has_next_page": False}}
                with patch.object(wp1_target, "request_json", return_value=(200, response)):
                    with self.assertRaises(ValueError):
                        wp1_target.sync_schemas(root, "https://us.api.konghq.com", target, "token")
                self.assertEqual(writes, [])

    def test_redirects_and_http_error_bodies_are_rejected_without_leaking(self):
        request = object()
        self.assertIsNone(wp1_target.RejectRedirects().redirect_request(request, None, 302, "found", {}, "https://evil.test"))
        from urllib.error import HTTPError

        error = HTTPError("https://konnect.test", 302, "found", {}, None)
        error.fp = type("Body", (), {"read": lambda self: b"TOKEN_AND_RAW_LUA_SENTINEL", "close": lambda self: None})()
        with patch.object(wp1_target, "build_opener") as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaises(ValueError) as raised:
                wp1_target.request_json("https://konnect.test", "token-sentinel")
        message = str(raised.exception)
        self.assertIn("HTTP 302", message)
        self.assertNotIn("TOKEN_AND_RAW_LUA_SENTINEL", message)
        self.assertNotIn("token-sentinel", message)

    def test_read_only_metadata_must_match_id_name_and_both_endpoints(self):
        target = self.targets["api"]
        remote = {
            "data": {
                "id": target["control_plane_id"],
                "name": target["control_plane_name"],
                "config": {
                    "control_plane_endpoint": target["control_plane_endpoint"],
                    "telemetry_endpoint": target["telemetry_endpoint"],
                },
            }
        }
        with patch.object(wp1_target, "request_json", return_value=(200, remote)):
            wp1_target.verify_remote_target("https://us.api.konghq.com", target, "token")
        for key, value in (
            ("id", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            ("name", "wrong-name"),
        ):
            bad = copy.deepcopy(remote)
            bad["data"][key] = value
            with patch.object(wp1_target, "request_json", return_value=(200, bad)):
                with self.assertRaisesRegex(ValueError, "metadata does not match"):
                    wp1_target.verify_remote_target("https://us.api.konghq.com", target, "token")
        for key in ("control_plane_endpoint", "telemetry_endpoint"):
            bad = copy.deepcopy(remote)
            bad["data"]["config"][key] = "https://wrong.example"
            with patch.object(wp1_target, "request_json", return_value=(200, bad)):
                with self.assertRaisesRegex(ValueError, "metadata does not match"):
                    wp1_target.verify_remote_target("https://us.api.konghq.com", target, "token")

    def test_render_then_preflight_keeps_manifest_shape_and_fails_before_token(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "infra").mkdir()
            (root / "kong/foundation").mkdir(parents=True)
            for filename in ("api.yaml", "third-party.yaml"):
                (root / "kong/foundation" / filename).write_bytes((source / "kong/foundation" / filename).read_bytes())
            (root / ".env").write_text(
                "TF_VAR_control_plane_name=keycloak-fapi2-demo\n"
                "TF_VAR_third_party_control_plane_name=keycloak-fapi2-third-party-demo\n"
            )
            terraform = root / "terraform"
            terraform.write_text(
                "#!/usr/bin/env python3\n"
                "import json\n"
                "print(json.dumps({"
                "'api': {'control_plane_id':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','control_plane_name':'keycloak-fapi2-demo','control_plane_endpoint':'https://api.cp.konghq.com','telemetry_endpoint':'https://api.tp.konghq.com'},"
                "'third-party': {'control_plane_id':'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','control_plane_name':'keycloak-fapi2-third-party-demo','control_plane_endpoint':'https://third.cp.konghq.com','telemetry_endpoint':'https://third.tp.konghq.com'}"
                "}))\n"
            )
            terraform.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}"}
            subprocess.run([sys.executable, str(source / "scripts/render-runtime-env.py"), str(root)], check=True, env=env, capture_output=True, text=True)
            manifest = json.loads((root / ".generated/gateway_targets.json").read_text())
            self.assertEqual(manifest["targets"]["api"]["control_plane_id"], "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            self.assertEqual(manifest["targets"]["api"]["control_plane_name"], "keycloak-fapi2-demo")
            self.assertEqual(manifest["targets"]["third-party"]["control_plane_id"], "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
            self.assertEqual(manifest["targets"]["third-party"]["control_plane_name"], "keycloak-fapi2-third-party-demo")
            for target in manifest["targets"].values():
                self.assertEqual(set(target), {"control_plane_id", "control_plane_name", "control_plane_endpoint", "telemetry_endpoint"})
            runtime = (root / ".generated/runtime.env").read_text()
            self.assertIn("KONNECT_API_CP_HOST=api.cp.konghq.com", runtime)
            self.assertIn("KONNECT_THIRD_PARTY_TP_HOST=third.tp.konghq.com", runtime)
            self.assertNotIn("KONNECT_CP_HOST=", runtime)

            command = [sys.executable, str(TARGET_CLI), "schema-check", "--root", str(root), "--gateway", "third-party"]
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("KONNECT_TOKEN is required after local target validation", result.stderr)
            self.assertNotIn("token", (root / ".env").read_text().lower())

            command_stage = [*command, "--stage", "foundation"]
            result = subprocess.run(command_stage, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("schema operations do not accept STAGE", result.stderr)

            manifest["targets"]["third-party"]["control_plane_id"] = "../../unsafe"
            (root / ".generated/gateway_targets.json").write_text(json.dumps(manifest))
            (root / ".env").write_text("KONNECT_TOKEN=token-sentinel\n")
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("is not a UUID", result.stderr)
            self.assertNotIn("token-sentinel", result.stderr)

            # A direct edit to ownership tags is rejected locally before credentials are read.
            (root / ".env").write_text("KONNECT_TOKEN=token-sentinel\n")
            foundation = root / "kong/foundation/third-party.yaml"
            foundation.write_text(foundation.read_text().replace("fapi2-foundation", "tampered"))
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("foundation state select_tags were changed", result.stderr)
            self.assertNotIn("token-sentinel", result.stderr)

    def test_semantic_yaml_gate_rejects_duplicate_keys_empty_entities_and_swaps(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_cli_fixture(root, source)
            path = root / "kong/foundation/third-party.yaml"
            baseline = path.read_text()
            cases = [
                baseline.replace('_format_version: "3.0"\n', '_format_version: "3.0"\n_info: {select_tags: [fapi2-demo, fapi2-foundation]}\n'),
                baseline.replace("plugins:\n", "services: []\nplugins:\n"),
                baseline.replace("plugins:\n", "plugins:\n  - id: duplicate\n    name: fapi-as-mtls-transport\n    id: duplicate-again\n"),
                baseline.replace("client_id: third-party-fapi-mtls", "client_id: third-party-fapi-pkj-mtls"),
                baseline.replace("certificate_file: /etc/kong/fapi/route-a.crt", "certificate_file: /etc/kong/fapi/route-b.crt"),
                baseline.replace("    enabled: true\n", "    enabled: true\n    route: 754519ff-b0b9-5ed5-94c0-e453d260c6c4\n"),
                baseline.replace('{vault://env/ROUTE_A_TLS_KEY}', '{vault://env/ROUTE_B_TLS_KEY}'),
            ]
            command = [sys.executable, str(TARGET_CLI), "schema-check", "--root", str(root), "--gateway", "third-party"]
            for content in cases:
                path.write_text(content)
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("token-sentinel", result.stderr)
            self.assertTrue(all(not marker.exists() for marker in (root / "deck-called", root / "network-called")))

            # Exercise the real launcher entrypoint: local YAML rejection must precede metadata, schema, and decK.
            invalid = baseline.replace('{vault://env/ROUTE_A_TLS_KEY}', '{vault://env/ROUTE_B_TLS_KEY}')
            path.write_text(invalid)
            with patch.object(sys, "argv", [str(RUN_DECK), "diff", "--root", str(root), "--gateway", "third-party", "--stage", "foundation"]), \
                 patch.object(run_deck, "verify_remote_target") as metadata, \
                 patch.object(run_deck, "check_schemas") as schemas, \
                 patch.object(run_deck.subprocess, "run") as deck_call:
                with self.assertRaisesRegex(ValueError, "secret reference"):
                    run_deck.main()
                metadata.assert_not_called()
                schemas.assert_not_called()
                deck_call.assert_not_called()

            api_path = root / "kong/foundation/api.yaml"
            api_baseline = api_path.read_text()
            api_mutations = [
                api_baseline.replace('{vault://env/API_INTROSPECTION_KEY}', '{vault://env/API_UPSTREAM_KEY}'),
                api_baseline.replace('env "DECK_API_INTROSPECTION_CERT_YAML"', 'env "DECK_API_UPSTREAM_CERT_YAML"'),
                api_baseline.replace('cert: "${{ env "DECK_API_INTROSPECTION_CERT_YAML" }}"', 'cert: "inline-public-cert"'),
            ]
            with patch.object(sys, "argv", [str(RUN_DECK), "diff", "--root", str(root), "--gateway", "api", "--stage", "foundation"]), \
                 patch.object(run_deck, "verify_remote_target") as metadata, \
                 patch.object(run_deck.subprocess, "run") as deck_call, \
                 patch("sys.stderr", new_callable=__import__("io").StringIO):
                for content in api_mutations:
                    api_path.write_text(content)
                    with self.assertRaises(ValueError):
                        run_deck.main()
                    metadata.assert_not_called()
                    deck_call.assert_not_called()

    def test_run_deck_entrypoint_owns_preflight_and_sanitizes_decK_output(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_cli_fixture(root, source)
            events = []
            fake_result = subprocess.CompletedProcess(
                args=["deck"], returncode=7,
                stdout="public cert -----BEGIN CERTIFICATE-----\nPEM_SENTINEL\n-----END CERTIFICATE----- token-sentinel PRIVATE_SENTINEL",
                stderr="private PRIVATE_SENTINEL token-sentinel",
            )
            with patch.object(sys, "argv", [str(RUN_DECK), "diff", "--root", str(root), "--gateway", "api", "--stage", "foundation"]), \
                 patch.object(run_deck, "verify_remote_target", side_effect=lambda *a: events.append("metadata")), \
                 patch.object(run_deck, "check_schemas", side_effect=lambda *a: events.append("schema")), \
                 patch.object(run_deck.subprocess, "run", side_effect=lambda command, **kwargs: (events.append(("deck", command)), fake_result)[1]), \
                 patch("sys.stdout", new_callable=__import__("io").StringIO) as out, \
                 patch("sys.stderr", new_callable=__import__("io").StringIO) as err:
                self.assertEqual(run_deck.main(), 7)
            self.assertEqual(events[0:2], ["metadata", "schema"])
            self.assertEqual(events[2][0], "deck")
            command = events[2][1]
            self.assertEqual(command[3], str((root / "kong/foundation/api.yaml").resolve()))
            self.assertNotIn("--state", command)
            for captured in (out.getvalue(), err.getvalue()):
                for sentinel in ("PEM_SENTINEL", "PRIVATE_SENTINEL", "token-sentinel"):
                    self.assertNotIn(sentinel, captured)

            # A direct arbitrary state argument is rejected by argparse before preflight, network, or decK.
            with patch.object(sys, "argv", [str(RUN_DECK), "diff", "--root", str(root), "--gateway", "api", "--stage", "foundation", "--state", "/tmp/evil.yaml"]), \
                 patch.object(run_deck, "verify_remote_target") as metadata, \
                 patch.object(run_deck.subprocess, "run") as deck_call, \
                 patch("sys.stderr", new_callable=__import__("io").StringIO):
                with self.assertRaises(SystemExit):
                    run_deck.main()
                metadata.assert_not_called()
                deck_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
