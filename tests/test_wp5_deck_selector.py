#!/usr/bin/env python3
"""Local WP5 decK selector checks; no external target or decK process is used."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import wp1_target  # noqa: E402

RUN_DECK = ROOT / "scripts/run-deck.py"
SPEC = importlib.util.spec_from_file_location("wp5_run_deck", RUN_DECK)
run_deck = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(run_deck)


def fixture_tree(root: Path) -> None:
    (root / "infra").mkdir()
    (root / "kong/foundation").mkdir(parents=True)
    (root / ".generated/evidence").mkdir(parents=True)
    for source, target in (
        (ROOT / "kong/foundation/third-party.yaml", root / "kong/foundation/third-party.yaml"),
        (ROOT / "kong/third-party-gateway.yaml", root / "kong/third-party-gateway.yaml"),
    ):
        target.write_bytes(source.read_bytes())

    cert_key = root / "demo-ca.key"
    cert_file = root / "demo-ca.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cert_key),
         "-out", str(cert_file), "-days", "1", "-subj", "/CN=wp5-selector-fixture"],
        capture_output=True,
        check=True,
    )
    certificate = cert_file.read_text()
    private_key = "-----BEGIN " + "PRIVATE KEY-----\nprivate-key-sentinel\n-----END PRIVATE KEY-----\n"
    (root / ".env").write_text(
        "KONNECT_TOKEN=token-sentinel\n"
        "TF_VAR_control_plane_name=keycloak-fapi2-demo\n"
        "TF_VAR_third_party_control_plane_name=keycloak-fapi2-third-party-demo\n"
    )
    (root / ".generated/gateway_targets.json").write_text(json.dumps({
        "konnect_server_url": "https://us.api.konghq.com",
        "targets": {
            "api": {
                "control_plane_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "control_plane_name": "keycloak-fapi2-demo",
                "control_plane_endpoint": "https://api.cp.konghq.com",
                "telemetry_endpoint": "https://api.tp.konghq.com",
            },
            "third-party": {
                "control_plane_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "control_plane_name": "keycloak-fapi2-third-party-demo",
                "control_plane_endpoint": "https://third.cp.konghq.com",
                "telemetry_endpoint": "https://third.tp.konghq.com",
            },
        },
    }))
    (root / ".generated/deck.env").write_text("DECK_ROUTE_B_JWK_KID=selector-fixture-kid\n")
    role_file = root / ".generated/runtime-third-party.json"
    role_file.write_text(json.dumps({
        "DECK_FAPI_CA_CERT_YAML": certificate,
        "DECK_ROUTE_A_TLS_CERT_YAML": certificate,
        "ROUTE_A_TLS_KEY": private_key,
        "DECK_ROUTE_B_TLS_CERT_YAML": certificate,
        "ROUTE_B_TLS_KEY": private_key,
    }))
    role_file.chmod(0o600)


def additive_report() -> dict:
    identities = [
        ("service", "third-party-route-a-api"),
        ("service", "third-party-route-b-api"),
        ("route", "third-party-route-a"),
        ("route", "third-party-route-b"),
        ("plugin", "cors for service third-party-route-a-api"),
        ("plugin", "openid-connect for service third-party-route-a-api"),
        ("plugin", "request-transformer for service third-party-route-a-api"),
        ("plugin", "cors for service third-party-route-b-api"),
        ("plugin", "fapi-client-auth-bridge for service third-party-route-b-api"),
        ("plugin", "openid-connect for service third-party-route-b-api"),
        ("plugin", "request-transformer for service third-party-route-b-api"),
    ]
    entries = [
        {"kind": kind, "name": name, "body": {
            "old": None,
            "new": {"id": f"entity-{index + 1}", "name": name, "config": {"enabled": True}},
        }}
        for index, (kind, name) in enumerate(identities)
    ]
    return {
        "changes": {"creating": entries, "updating": [], "deleting": []},
        "summary": {"creating": 11, "updating": 0, "deleting": 0, "total": 11},
        "warnings": [],
        "errors": [],
    }


def write_wp5_receipt(root: Path, report: dict) -> dict:
    info = wp1_target.local_manifest(root, "third-party", "runtime", "sync")
    state = root / "kong/third-party-gateway.yaml"
    role_values = wp1_target.validate_role_values(
        "third-party",
        run_deck.read_private_role_file(
            root / ".generated/runtime-third-party.json", require_private_mode=True
        ),
    )
    operations, digest = run_deck.parse_sanitized_runtime_diff(json.dumps(report), [])
    receipt = {
        "schema_version": 1,
        "scope": "third-party-runtime",
        "approved": True,
        "target_sha256": run_deck.canonical_sha256(info["target"]),
        "state_sha256": run_deck.file_sha256(state),
        "role_inputs_sha256": run_deck.canonical_sha256(role_values),
        "diff_sha256": digest,
        **operations,
    }
    path = root / run_deck.WP5_APPROVAL_RELATIVE
    path.write_text(json.dumps(receipt))
    path.chmod(0o600)
    return receipt


class WP5DeckSelectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        fixture_tree(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_local_runtime_validate_and_selector_are_read_only(self):
        result = wp1_target.local_manifest(self.root, "third-party", "runtime", "validate")
        self.assertEqual(result, {})
        selected = wp1_target.local_manifest(self.root, "third-party", "runtime", "diff")
        self.assertEqual(selected["target"]["control_plane_id"], "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        selected_sync = wp1_target.local_manifest(self.root, "third-party", "runtime", "sync")
        self.assertEqual(selected_sync["target"], selected["target"])
        with patch.object(sys, "argv", [
            str(ROOT / "scripts/wp1_target.py"), "deck-validate", "--root", str(self.root),
            "--gateway", "third-party", "--stage", "runtime",
        ]):
            self.assertEqual(wp1_target.main(), 0)

    def test_runtime_guard_rejects_changes_to_fixed_tls_and_oidc_contract(self):
        source = self.root / "kong/third-party-gateway.yaml"
        baseline = wp1_target._parse_foundation(source)
        mutations = [
            lambda state: state["_info"].update(select_tags=["fapi2-demo", "fapi2-foundation"]),
            lambda state: state["services"][0].update(id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            lambda state: state["services"][0]["routes"][0].update(id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            lambda state: state["services"][1]["plugins"][1].update(id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            lambda state: state["services"][0].update(tls_verify=False),
            lambda state: state["services"][0].update(ca_certificates=[]),
            lambda state: state["services"][0]["plugins"][1]["config"].update(login_tokens=["cached"]),
            lambda state: state["services"][0]["plugins"][1]["config"].update(login_tokens=None),
            lambda state: state["services"][0]["plugins"][1]["config"].update(logout_revoke_refresh_token=False),
            lambda state: state["plugins"][0]["config"].update(
                token_url="http://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token"
            ),
            lambda state: state["services"][1]["plugins"][2]["config"].update(
                pushed_authorization_request_endpoint_auth_method="tls_client_auth"
            ),
            lambda state: state["services"][1]["plugins"][2]["config"].update(
                token_endpoint_auth_method="private_key_jwt"
            ),
            lambda state: state["services"][1]["plugins"][1]["config"].update(
                assertion_delivery="header"
            ),
            lambda state: state["certificates"].pop(),
            lambda state: state["ca_certificates"][0].update(cert="changed CA"),
        ]
        for mutate in mutations:
            state = copy.deepcopy(baseline)
            mutate(state)
            source.write_text(yaml.safe_dump(state, sort_keys=False))
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                wp1_target.validate_third_party_runtime_state(self.root)
        source.write_text((ROOT / "kong/third-party-gateway.yaml").read_text())
        self.assertEqual(
            wp1_target.validate_third_party_runtime_state(self.root)["_info"],
            {"select_tags": ["fapi2-demo"]},
        )

    def test_runtime_diff_prints_sanitized_operations_and_never_uses_api_receipt(self):
        report = {
            "changes": {
                "creating": [{"kind": "plugin", "name": "token-sentinel", "body": {
                    "old": None, "new": {"private_key": "private-key-sentinel"},
                }}],
                "updating": [{"kind": "service", "name": "third-party-route-a-api", "body": {
                    "old": {"cert": "-----BEGIN CERTIFICATE----- secret"}, "new": {},
                }}],
                "deleting": [],
            },
            "summary": {"creating": 1, "updating": 1, "deleting": 0, "total": 2},
            "warnings": [],
            "errors": [],
        }
        calls = []

        def fake_deck(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, json.dumps(report), "")

        with patch.object(sys, "argv", [
            str(RUN_DECK), "diff", "--root", str(self.root), "--gateway", "third-party", "--stage", "runtime",
        ]), patch.object(run_deck, "verify_remote_target") as remote, \
             patch.object(run_deck, "verify_shared_api_ca") as api_ca, \
             patch.object(run_deck, "check_schemas") as schemas, \
             patch.object(run_deck, "read_migration_approval", side_effect=AssertionError("API receipt must not be used")) as receipt, \
             patch.object(run_deck, "run_deck_subprocess", side_effect=fake_deck), \
             patch("sys.stdout", new_callable=__import__("io").StringIO) as output, \
             patch("sys.stderr", new_callable=__import__("io").StringIO) as error:
            self.assertEqual(run_deck.main(), 0)

        remote.assert_called_once()
        api_ca.assert_not_called()
        schemas.assert_called_once()
        receipt.assert_not_called()
        self.assertEqual(len(calls), 1)
        command, environment = calls[0]
        self.assertEqual(command[2], "diff")
        self.assertEqual(command[3], str((self.root / "kong/third-party-gateway.yaml").resolve()))
        self.assertIn("--json-output", command)
        self.assertIn("--no-color", command)
        self.assertEqual(command[command.index("--parallelism") + 1], "1")
        self.assertIn("--no-mask-deck-env-vars-value", command)
        self.assertNotIn("KONNECT_TOKEN", environment["environment"])
        self.assertEqual(environment["environment"]["DECK_KONNECT_TOKEN"], "token-sentinel")
        captured = output.getvalue() + error.getvalue()
        for secret in ("token-sentinel", "private-key-sentinel", "BEGIN CERTIFICATE"):
            self.assertNotIn(secret, captured)
        self.assertIn("WP5_THIRD_PARTY_RUNTIME_STATE_SHA256=", captured)
        self.assertIn("WP5_THIRD_PARTY_RUNTIME_ROLE_INPUTS_SHA256=", captured)
        self.assertIn("WP5_THIRD_PARTY_RUNTIME_TARGET_SHA256=", captured)
        self.assertRegex(captured, r"WP5_THIRD_PARTY_RUNTIME_DIFF_SHA256=[0-9a-f]{64}")
        self.assertNotIn("WP3_MIGRATION", captured)
        self.assertIn("[REDACTED]", captured)

    def test_runtime_sync_requires_explicit_approval_before_auth_or_deck(self):
        with patch.object(sys, "argv", [
            str(RUN_DECK), "sync", "--root", str(self.root), "--gateway", "third-party", "--stage", "runtime",
        ]), patch.dict(os.environ, {"WP5_THIRD_PARTY_RUNTIME_APPROVED": "NO"}), \
             patch.object(run_deck, "verify_remote_target") as remote, \
             patch.object(run_deck, "check_schemas") as schemas, \
             patch.object(run_deck, "read_migration_approval") as receipt, \
             patch.object(run_deck, "run_deck_subprocess") as deck:
            with self.assertRaisesRegex(ValueError, "WP5_THIRD_PARTY_RUNTIME_APPROVED=YES"):
                run_deck.main()
        remote.assert_not_called()
        schemas.assert_not_called()
        receipt.assert_not_called()
        deck.assert_not_called()

    def test_runtime_sync_requires_private_review_receipt_before_auth(self):
        with patch.object(sys, "argv", [
            str(RUN_DECK), "sync", "--root", str(self.root), "--gateway", "third-party", "--stage", "runtime",
        ]), patch.dict(os.environ, {"WP5_THIRD_PARTY_RUNTIME_APPROVED": "YES"}), \
             patch.object(run_deck, "verify_remote_target") as remote, \
             patch.object(run_deck, "check_schemas") as schemas, \
             patch.object(run_deck, "run_deck_subprocess") as deck:
            with self.assertRaisesRegex(ValueError, "approval receipt"):
                run_deck.main()
        remote.assert_not_called()
        schemas.assert_not_called()
        deck.assert_not_called()

    def test_runtime_sync_receipt_binds_target_state_and_role_inputs_before_auth(self):
        receipt = write_wp5_receipt(self.root, additive_report())
        path = self.root / run_deck.WP5_APPROVAL_RELATIVE
        for field in ("target_sha256", "state_sha256", "role_inputs_sha256"):
            altered = dict(receipt)
            altered[field] = "0" * 64
            path.write_text(json.dumps(altered))
            path.chmod(0o600)
            with self.subTest(field=field), patch.object(sys, "argv", [
                str(RUN_DECK), "sync", "--root", str(self.root), "--gateway", "third-party", "--stage", "runtime",
            ]), patch.dict(os.environ, {"WP5_THIRD_PARTY_RUNTIME_APPROVED": "YES"}), \
                 patch.object(run_deck, "verify_remote_target") as remote, \
                 patch.object(run_deck, "run_deck_subprocess") as deck:
                with self.assertRaisesRegex(ValueError, "does not match current target, state, or role inputs"):
                    run_deck.main()
            remote.assert_not_called()
            deck.assert_not_called()

    def test_runtime_sync_rejects_wrong_same_count_global_plugin_before_auth(self):
        report = additive_report()
        global_plugin = report["changes"]["creating"][-1]
        global_plugin["name"] = "fapi-as-mtls-transport"
        global_plugin["body"]["new"]["name"] = "fapi-as-mtls-transport"
        operations, _digest = run_deck.parse_sanitized_runtime_diff(json.dumps(report), [])
        self.assertEqual(operations["summary"], run_deck.WP5_EXPECTED_SUMMARY)
        with self.assertRaisesRegex(ValueError, "identities differ"):
            run_deck.validate_wp5_additive_scope(operations)
        write_wp5_receipt(self.root, report)

        with patch.object(sys, "argv", [
            str(RUN_DECK), "sync", "--root", str(self.root), "--gateway", "third-party", "--stage", "runtime",
        ]), patch.dict(os.environ, {"WP5_THIRD_PARTY_RUNTIME_APPROVED": "YES"}), \
             patch.object(run_deck, "verify_remote_target") as remote, \
             patch.object(run_deck, "run_deck_subprocess") as deck:
            with self.assertRaisesRegex(ValueError, "identities differ from the fixed additive scope"):
                run_deck.main()
        remote.assert_not_called()
        deck.assert_not_called()

    def test_runtime_sync_rechecks_exact_reviewed_diff_and_withholds_deck_output(self):
        report = additive_report()
        receipt = write_wp5_receipt(self.root, report)
        calls = []

        def fake_deck(command, **kwargs):
            calls.append(list(command))
            if command[2] == "diff":
                return subprocess.CompletedProcess(command, 0, json.dumps(report), "")
            return subprocess.CompletedProcess(command, 0, "raw entity body", "raw private output")

        with patch.object(sys, "argv", [
            str(RUN_DECK), "sync", "--root", str(self.root), "--gateway", "third-party", "--stage", "runtime",
        ]), patch.dict(os.environ, {"WP5_THIRD_PARTY_RUNTIME_APPROVED": "YES"}), \
             patch.object(run_deck, "verify_remote_target") as remote, \
             patch.object(run_deck, "verify_shared_api_ca") as api_ca, \
             patch.object(run_deck, "check_schemas") as schemas, \
             patch.object(run_deck, "run_deck_subprocess", side_effect=fake_deck), \
             patch("sys.stdout", new_callable=__import__("io").StringIO) as output:
            self.assertEqual(run_deck.main(), 0)

        remote.assert_called_once()
        api_ca.assert_not_called()
        schemas.assert_called_once()
        self.assertEqual([command[2] for command in calls], ["diff", "sync"])
        for command in calls:
            self.assertEqual(command[command.index("--parallelism") + 1], "1")
        self.assertIn("--no-mask-deck-env-vars-value", calls[0])
        self.assertNotIn("--no-mask-deck-env-vars-value", calls[1])
        self.assertIn("approved additive 11-entity scope", output.getvalue())
        self.assertNotIn("raw entity body", output.getvalue())
        self.assertNotIn("raw private output", output.getvalue())
        self.assertEqual(receipt["summary"], run_deck.WP5_EXPECTED_SUMMARY)

    def test_runtime_sync_rejects_changed_or_noop_diff_without_sync(self):
        approved = additive_report()
        write_wp5_receipt(self.root, approved)
        changed = copy.deepcopy(approved)
        changed["changes"]["creating"][0]["body"]["new"]["config"]["session_secret"] = "changed-session-secret-sentinel"
        approved_view, approved_digest = run_deck.parse_sanitized_runtime_diff(json.dumps(approved), [])
        changed_view, changed_digest = run_deck.parse_sanitized_runtime_diff(json.dumps(changed), [])
        self.assertEqual(changed_view, approved_view)
        self.assertNotEqual(changed_digest, approved_digest)
        self.assertNotIn("changed-session-secret-sentinel", json.dumps(changed_view))
        noop = {
            "changes": {"creating": [], "updating": [], "deleting": []},
            "summary": {"creating": 0, "updating": 0, "deleting": 0, "total": 0},
            "warnings": [], "errors": [],
        }

        for report in (changed, noop):
            calls = []

            def fake_deck(command, **kwargs):
                calls.append(command[2])
                return subprocess.CompletedProcess(command, 0, json.dumps(report), "")

            with self.subTest(summary=report["summary"]), patch.object(sys, "argv", [
                str(RUN_DECK), "sync", "--root", str(self.root), "--gateway", "third-party", "--stage", "runtime",
            ]), patch.dict(os.environ, {"WP5_THIRD_PARTY_RUNTIME_APPROVED": "YES"}), \
                 patch.object(run_deck, "verify_remote_target"), patch.object(run_deck, "check_schemas"), \
                 patch.object(run_deck, "run_deck_subprocess", side_effect=fake_deck):
                with self.assertRaisesRegex(ValueError, "not the reviewed additive|changed after Root review"):
                    run_deck.main()
            self.assertEqual(calls, ["diff"])


if __name__ == "__main__":
    unittest.main()
