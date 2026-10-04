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
    (root / ".generated").mkdir()
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
        with patch.object(sys, "argv", [
            str(ROOT / "scripts/wp1_target.py"), "deck-validate", "--root", str(self.root),
            "--gateway", "third-party", "--stage", "runtime",
        ]):
            self.assertEqual(wp1_target.main(), 0)
        with self.assertRaisesRegex(ValueError, "third-party runtime sync is disabled"):
            wp1_target.local_manifest(self.root, "third-party", "runtime", "sync")

    def test_runtime_guard_rejects_changes_to_fixed_tls_and_oidc_contract(self):
        source = self.root / "kong/third-party-gateway.yaml"
        baseline = wp1_target._parse_foundation(source)
        mutations = [
            lambda state: state["_info"].update(select_tags=["fapi2-demo", "fapi2-foundation"]),
            lambda state: state["services"][0]["routes"][0].update(id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            lambda state: state["services"][0].update(tls_verify=False),
            lambda state: state["services"][0].update(ca_certificates=[]),
            lambda state: state["services"][0]["plugins"][1]["config"].update(login_tokens=["cached"]),
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
        self.assertNotIn("KONNECT_TOKEN", environment["environment"])
        self.assertEqual(environment["environment"]["DECK_KONNECT_TOKEN"], "token-sentinel")
        captured = output.getvalue() + error.getvalue()
        for secret in ("token-sentinel", "private-key-sentinel", "BEGIN CERTIFICATE"):
            self.assertNotIn(secret, captured)
        self.assertIn("WP5_THIRD_PARTY_RUNTIME_STATE_SHA256=", captured)
        self.assertIn("WP5_THIRD_PARTY_RUNTIME_ROLE_INPUTS_SHA256=", captured)
        self.assertNotIn("WP3_MIGRATION", captured)
        self.assertIn("[REDACTED]", captured)

    def test_runtime_sync_is_always_refused_before_auth_or_deck(self):
        with patch.object(sys, "argv", [
            str(RUN_DECK), "sync", "--root", str(self.root), "--gateway", "third-party", "--stage", "runtime",
        ]), patch.object(run_deck, "verify_remote_target") as remote, \
             patch.object(run_deck, "check_schemas") as schemas, \
             patch.object(run_deck, "read_migration_approval") as receipt, \
             patch.object(run_deck, "run_deck_subprocess") as deck:
            with self.assertRaisesRegex(ValueError, "third-party runtime sync is disabled"):
                run_deck.main()
        remote.assert_not_called()
        schemas.assert_not_called()
        receipt.assert_not_called()
        deck.assert_not_called()


if __name__ == "__main__":
    unittest.main()
