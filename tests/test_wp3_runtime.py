#!/usr/bin/env python3
"""Pure tests for WP3 state ownership and decK migration normalization."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import wp3_runtime

_RUN_DECK_SPEC = importlib.util.spec_from_file_location("wp3_run_deck", ROOT / "scripts/run-deck.py")
run_deck = importlib.util.module_from_spec(_RUN_DECK_SPEC)
assert _RUN_DECK_SPEC.loader is not None
_RUN_DECK_SPEC.loader.exec_module(run_deck)

FIXTURE_ROLE_VALUES = {
    "DECK_FAPI_CA_CERT_YAML": "fixture-public-ca",
    "DECK_API_INTROSPECTION_CERT_YAML": "fixture-public-cert",
    "API_INTROSPECTION_KEY": "fixture-private-role-value",
}
FIXTURE_CONTROL_PLANE_ID = "fixture-api-control-plane"


def prepare_migration_root(root: Path, *, role_values=None, report=None):
    role_values = dict(FIXTURE_ROLE_VALUES if role_values is None else role_values)
    report = make_report() if report is None else report
    generated = root / ".generated"
    evidence = generated / "evidence"
    state_path = root / "kong/api-gateway.yaml"
    role_path = generated / "runtime-api.json"
    generated.mkdir(mode=0o700, parents=True, exist_ok=True)
    evidence.mkdir(mode=0o700, exist_ok=True)
    (root / "kong").mkdir(mode=0o700, exist_ok=True)
    generated.chmod(0o700)
    evidence.chmod(0o700)
    state_path.write_text("fixture API runtime state\n", encoding="utf-8")
    role_path.write_text(json.dumps(role_values), encoding="utf-8")
    role_path.chmod(0o600)
    operations, digest = wp3_runtime.parse_deck_diff_report(json.dumps(report))
    receipt = {
        "schema_version": 1,
        "scope": "api-runtime-migration",
        "approved": True,
        "control_plane_id": FIXTURE_CONTROL_PLANE_ID,
        "state_sha256": wp3_runtime.file_sha256(state_path),
        "role_inputs_sha256": wp3_runtime.canonical_sha256(role_values),
        "diff_sha256": digest,
        "summary": operations["summary"],
        "operations": operations["operations"],
    }
    receipt_path = evidence / "wp3-api-runtime-migration-approval.json"
    receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    receipt_path.chmod(0o600)
    return role_values, report, receipt, receipt_path


def fake_target_info():
    return {
        "manifest": {"konnect_server_url": "https://konnect.fixture.invalid"},
        "target": {
            "control_plane_id": FIXTURE_CONTROL_PLANE_ID,
            "control_plane_name": "fixture-api",
        },
    }


def make_report():
    creates = []
    for name, entity_id in wp3_runtime.RUNTIME_ENTITY_IDS.items():
        kind = wp3_runtime.EXPECTED_RUNTIME_CREATE_KINDS[name]
        entity = {
            "id": entity_id,
            "name": name,
            "tags": ["fapi2-demo", "api"],
            "config": {"fixture": f"config-{name}"},
        }
        report_name = name
        if kind == "route":
            entity["service"] = {
                "id": wp3_runtime.RUNTIME_ENTITY_IDS[wp3_runtime.RUNTIME_SERVICE_NAME],
                "name": wp3_runtime.RUNTIME_SERVICE_NAME,
            }
        elif kind == "plugin":
            entity["route"] = {
                "id": wp3_runtime.RUNTIME_ENTITY_IDS[wp3_runtime.RUNTIME_ROUTE_NAME],
                "name": wp3_runtime.RUNTIME_ROUTE_NAME,
            }
            report_name = f"{name} for route {wp3_runtime.RUNTIME_ROUTE_NAME}"
        creates.append({
            "kind": kind,
            "name": report_name,
            "body": {
                "new": entity,
                "old": None,
            },
        })

    service_ids = {
        "route-a": "90000000-0000-4000-8000-000000000001",
        "route-b": "90000000-0000-4000-8000-000000000002",
    }
    certificate_ids = {
        "route-a": "90000000-0000-4000-8000-000000000003",
        "route-b": "90000000-0000-4000-8000-000000000004",
    }
    deletes = []
    next_id = 5

    def add_delete(kind, name, entity, *, report_name=None):
        nonlocal next_id
        entity_id = entity.get("id")
        if entity_id is None:
            entity_id = f"90000000-0000-4000-8000-{next_id:012d}"
            next_id += 1
        entity["id"] = entity_id
        deletes.append({
            "kind": kind,
            "name": name if report_name is None else report_name,
            "body": {"new": entity, "old": None},
        })

    for service_name, tag in wp3_runtime.LEGACY_API_SERVICE_ROUTE_TAGS.items():
        add_delete("service", service_name, {
            "id": service_ids[tag],
            "name": service_name,
            "tags": ["fapi2-demo", tag],
            "client_certificate": {"id": certificate_ids[tag]},
            "ca_certificates": [wp3_runtime.SHARED_API_CA_ID],
            "protocol": "https",
        })
    for route_name, tag in wp3_runtime.LEGACY_API_ROUTE_SERVICE_TAGS.items():
        add_delete("route", route_name, {
            "name": route_name,
            "tags": ["fapi2-demo", tag],
            "service": {
                "id": service_ids[tag],
                "name": next(
                    service_name for service_name, service_tag
                    in wp3_runtime.LEGACY_API_SERVICE_ROUTE_TAGS.items()
                    if service_tag == tag
                ),
            },
            "paths": ["/fixture/" + tag],
        })
    for name, tag in wp3_runtime.LEGACY_API_PLUGIN_ROUTE_TAGS:
        service_name = next(
            service for service, service_tag in wp3_runtime.LEGACY_API_SERVICE_ROUTE_TAGS.items()
            if service_tag == tag
        )
        add_delete("plugin", name, {
            "name": name,
            "tags": ["fapi2-demo", tag],
            "service": {"id": service_ids[tag], "name": service_name},
            "config": {"fixture": f"{name}-{tag}"},
        }, report_name=f"{name} for service {service_name}")
    for tag, entity_id in certificate_ids.items():
        add_delete("certificate", f"{tag}-route-certificate", {
            "id": entity_id,
            "tags": ["fapi2-demo", tag],
            "certificate_sha256": ("a" if tag == "route-a" else "b") * 64,
        })

    return {
        "changes": {"creating": creates, "updating": [], "deleting": deletes},
        "summary": {"creating": 6, "updating": 0, "deleting": 13, "total": 19},
        "warnings": [],
        "errors": [],
    }


def make_noop_report():
    return {
        "changes": {"creating": [], "updating": [], "deleting": []},
        "summary": {"creating": 0, "updating": 0, "deleting": 0, "total": 0},
        "warnings": [],
        "errors": [],
    }


class WP3RuntimeTests(unittest.TestCase):
    def test_current_api_state_meets_fixed_ownership_contract(self):
        state = wp3_runtime.validate_api_runtime_state(ROOT)
        self.assertEqual(
            {entity["name"]: entity["id"] for entity in state["services"]},
            {"fapi-api-resource-server": wp3_runtime.RUNTIME_ENTITY_IDS["fapi-api-resource-server"]},
        )

    def test_runtime_validator_rejects_fixed_id_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp_root = Path(temporary)
            (temp_root / "kong/foundation").mkdir(parents=True)
            shutil.copy(ROOT / "kong/api-gateway.yaml", temp_root / "kong/api-gateway.yaml")
            shutil.copy(ROOT / "kong/foundation/api.yaml", temp_root / "kong/foundation/api.yaml")
            state_path = temp_root / "kong/api-gateway.yaml"
            state_path.write_text(
                state_path.read_text().replace(
                    wp3_runtime.RUNTIME_ENTITY_IDS["fapi-api-resource-server"],
                    "a5fe77b4-93fd-4f84-bb31-71c245dedd00",
                    1,
                )
            )
            with self.assertRaisesRegex(ValueError, "Resource Server Service contract"):
                wp3_runtime.validate_api_runtime_state(temp_root)

    def test_runtime_validator_rejects_query_guard_removal_or_source_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp_root = Path(temporary)
            (temp_root / "kong/foundation").mkdir(parents=True)
            shutil.copy(ROOT / "kong/foundation/api.yaml", temp_root / "kong/foundation/api.yaml")
            state_path = temp_root / "kong/api-gateway.yaml"
            source = (ROOT / "kong/api-gateway.yaml").read_text(encoding="utf-8")
            guard_start = source.index("          local function reject_query_authentication()")
            guard_end = source.index("\n  - name: openid-connect", guard_start)
            state_path.write_text(source[:guard_start] + source[guard_end:], encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "header-boundary guard changed"):
                wp3_runtime.validate_api_runtime_state(temp_root)

    def test_diff_hash_is_stable_when_dec_k_reorders_operations(self):
        first = make_report()
        second = copy.deepcopy(first)
        second["changes"]["creating"].reverse()
        first_operations, first_digest = wp3_runtime.parse_deck_diff_report(json.dumps(first))
        second_operations, second_digest = wp3_runtime.parse_deck_diff_report(json.dumps(second))
        self.assertEqual(first_operations, second_operations)
        self.assertEqual(first_digest, second_digest)

    def test_diff_digest_binds_full_config_and_existing_ids(self):
        baseline = make_report()
        _operations, baseline_digest = wp3_runtime.parse_deck_diff_report(json.dumps(baseline))
        altered_secret = copy.deepcopy(baseline)
        altered_secret["changes"]["deleting"][0]["body"]["new"]["client_secret"] = "private-new-value"
        _operations, secret_digest = wp3_runtime.parse_deck_diff_report(json.dumps(altered_secret))
        altered_id = copy.deepcopy(baseline)
        plugin_row = next(
            row for row in altered_id["changes"]["deleting"]
            if row["kind"] == "plugin" and row["body"]["new"]["name"] == "cors"
        )
        plugin_row["body"]["new"]["id"] = "90000000-0000-4000-8000-999999999999"
        _operations, id_digest = wp3_runtime.parse_deck_diff_report(json.dumps(altered_id))
        self.assertNotEqual(baseline_digest, secret_digest)
        self.assertNotEqual(baseline_digest, id_digest)

    def test_diff_parser_uses_dec_k_deletion_body_new_and_rejects_protected_id(self):
        report = make_report()
        report["changes"]["deleting"][0]["body"]["new"]["id"] = wp3_runtime.SHARED_API_CA_ID
        with self.assertRaisesRegex(ValueError, "protected"):
            wp3_runtime.parse_deck_diff_report(json.dumps(report))

    def test_diff_parser_rejects_create_identity_or_tag_drift(self):
        report = make_report()
        report["changes"]["creating"][0]["body"]["new"]["tags"] = ["fapi2-demo"]
        with self.assertRaisesRegex(ValueError, "ownership tags"):
            wp3_runtime.parse_deck_diff_report(json.dumps(report))

    def test_runtime_diff_validates_source_derived_plugin_descriptors_and_normalizes_identities(self):
        report = make_report()
        operations, _digest = wp3_runtime.parse_deck_diff_report(json.dumps(report))
        creates = operations["operations"]["creating"]
        self.assertEqual(
            {item["name"] for item in creates if item["kind"] == "plugin"},
            {"pre-function", "openid-connect", "tls-handshake-modifier", "tls-metadata-headers"},
        )
        wp3_runtime.validate_migration_approval_operations(operations["summary"], operations["operations"])

        bad_label = copy.deepcopy(report)
        plugin = next(
            row for row in bad_label["changes"]["creating"]
            if row["kind"] == "plugin" and row["body"]["new"]["name"] == "openid-connect"
        )
        plugin["name"] = "openid-connect for route unrelated-route"
        with self.assertRaisesRegex(ValueError, "descriptor or Route binding"):
            wp3_runtime.parse_deck_diff_report(json.dumps(bad_label))

        bad_route_name = copy.deepcopy(report)
        plugin = next(
            row for row in bad_route_name["changes"]["creating"]
            if row["kind"] == "plugin" and row["body"]["new"]["name"] == "openid-connect"
        )
        plugin["body"]["new"]["route"]["name"] = "unrelated-route"
        with self.assertRaisesRegex(ValueError, "descriptor or Route binding"):
            wp3_runtime.parse_deck_diff_report(json.dumps(bad_route_name))

        extra_route_field = copy.deepcopy(report)
        plugin = next(
            row for row in extra_route_field["changes"]["creating"]
            if row["kind"] == "plugin" and row["body"]["new"]["name"] == "openid-connect"
        )
        plugin["body"]["new"]["route"]["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "descriptor or Route binding"):
            wp3_runtime.parse_deck_diff_report(json.dumps(extra_route_field))

    def test_runtime_diff_rejects_legacy_plugin_descriptor_or_relation_drift(self):
        report = make_report()
        plugin = next(
            row for row in report["changes"]["deleting"]
            if row["kind"] == "plugin" and row["body"]["new"]["name"] == "openid-connect"
        )
        plugin["name"] = "openid-connect for service unrelated-service"
        with self.assertRaisesRegex(ValueError, "display name changed"):
            wp3_runtime.parse_deck_diff_report(json.dumps(report))

        report = make_report()
        plugin = next(
            row for row in report["changes"]["deleting"]
            if row["kind"] == "plugin" and row["body"]["new"]["name"] == "openid-connect"
        )
        plugin["body"]["new"]["service"]["name"] = "unrelated-service"
        with self.assertRaisesRegex(ValueError, "matching legacy Service"):
            wp3_runtime.parse_deck_diff_report(json.dumps(report))

        report = make_report()
        plugin = next(
            row for row in report["changes"]["deleting"]
            if row["kind"] == "plugin" and row["body"]["new"]["name"] == "openid-connect"
        )
        plugin["body"]["new"]["service"]["unexpected"] = "value"
        with self.assertRaisesRegex(ValueError, "matching legacy Service"):
            wp3_runtime.parse_deck_diff_report(json.dumps(report))

    def test_diff_parser_rejects_existing_entity_updates(self):
        report = make_report()
        current = {
            "id": "99333333-3333-4333-8333-333333333333",
            "name": "legacy-update",
            "tags": ["fapi2-demo"],
        }
        report["changes"]["updating"] = [{
            "kind": "service",
            "name": "legacy-update",
            "body": {"old": current, "new": {**current, "host": "changed"}},
        }]
        report["summary"]["updating"] = 1
        report["summary"]["total"] += 1
        with self.assertRaisesRegex(ValueError, "6/0/13"):
            wp3_runtime.parse_deck_diff_report(json.dumps(report))


    def test_runtime_diff_accepts_confirmed_noop_but_noop_cannot_be_approved(self):
        operations, digest = wp3_runtime.parse_deck_diff_report(json.dumps(make_noop_report()))
        self.assertEqual(operations["summary"], {"creating": 0, "updating": 0, "deleting": 0, "total": 0})
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        with self.assertRaisesRegex(ValueError, "6/0/13"):
            wp3_runtime.validate_migration_approval_operations(operations["summary"], operations["operations"])

    def test_runtime_diff_enforces_exact_legacy_names_tags_relations_and_counts(self):
        operations, _digest = wp3_runtime.parse_deck_diff_report(json.dumps(make_report()))
        self.assertEqual(operations["summary"], wp3_runtime.EXPECTED_RUNTIME_MIGRATION_SUMMARY)
        self.assertEqual(len(operations["operations"]["deleting"]), 13)

        bad_tag = make_report()
        bad_tag["changes"]["deleting"][0]["body"]["new"]["tags"] = ["fapi2-demo"]
        with self.assertRaisesRegex(ValueError, "legacy Route boundary"):
            wp3_runtime.parse_deck_diff_report(json.dumps(bad_tag))

        bad_relation = make_report()
        route = next(row for row in bad_relation["changes"]["deleting"] if row["kind"] == "route")
        route["body"]["new"]["service"]["id"] = "90000000-0000-4000-8000-888888888888"
        with self.assertRaisesRegex(ValueError, "matching legacy Service"):
            wp3_runtime.parse_deck_diff_report(json.dumps(bad_relation))

        unexpected_plugin = make_report()
        plugin = next(row for row in unexpected_plugin["changes"]["deleting"] if row["kind"] == "plugin")
        plugin["name"] = "custom-plugin"
        plugin["body"]["new"]["name"] = "custom-plugin"
        with self.assertRaisesRegex(ValueError, "legacy Route boundary"):
            wp3_runtime.parse_deck_diff_report(json.dumps(unexpected_plugin))

    def test_runtime_diff_binds_legacy_relations_without_pinning_old_ids(self):
        report = make_report()
        mapping = {}
        for index, row in enumerate(report["changes"]["deleting"], 20):
            old_id = row["body"]["new"]["id"]
            mapping[old_id] = f"80000000-0000-4000-8000-{index:012d}"
        for row in report["changes"]["deleting"]:
            entity = row["body"]["new"]
            entity["id"] = mapping[entity["id"]]
            certificate_id = entity.get("client_certificate", {}).get("id")
            if certificate_id in mapping:
                entity["client_certificate"]["id"] = mapping[certificate_id]
            relation = entity.get("service")
            if isinstance(relation, dict) and relation.get("id") in mapping:
                relation["id"] = mapping[relation["id"]]
        operations, _digest = wp3_runtime.parse_deck_diff_report(json.dumps(report))
        self.assertEqual(operations["summary"], wp3_runtime.EXPECTED_RUNTIME_MIGRATION_SUMMARY)

    def test_migration_approval_reader_accepts_bound_private_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, _report, receipt, _path = prepare_migration_root(root)
            read = wp3_runtime.read_migration_approval(root, FIXTURE_CONTROL_PLANE_ID, role_values)
            self.assertEqual(read["summary"], wp3_runtime.EXPECTED_RUNTIME_MIGRATION_SUMMARY)
            self.assertEqual(read["operations"], receipt["operations"])

    def test_migration_approval_reader_rejects_noop_scope_source_role_and_target_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, _report, _receipt, path = prepare_migration_root(root, report=make_noop_report())
            with self.assertRaisesRegex(ValueError, "6/0/13"):
                wp3_runtime.read_migration_approval(root, FIXTURE_CONTROL_PLANE_ID, role_values)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, _report, _receipt, _path = prepare_migration_root(root)
            with self.assertRaisesRegex(ValueError, "target and scope"):
                wp3_runtime.read_migration_approval(root, "wrong-control-plane", role_values)
            (root / "kong/api-gateway.yaml").write_text("changed fixture state\n")
            with self.assertRaisesRegex(ValueError, "current runtime state"):
                wp3_runtime.read_migration_approval(root, FIXTURE_CONTROL_PLANE_ID, role_values)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, _report, _receipt, _path = prepare_migration_root(root)
            altered = {**role_values, "API_INTROSPECTION_KEY": "changed-fixture-role"}
            with self.assertRaisesRegex(ValueError, "certificate role inputs"):
                wp3_runtime.read_migration_approval(root, FIXTURE_CONTROL_PLANE_ID, altered)

    def test_migration_approval_reader_rejects_protected_delete_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, _report, receipt, path = prepare_migration_root(root)
            receipt["operations"]["deleting"][0]["id"] = wp3_runtime.SHARED_API_CA_ID
            path.write_text(json.dumps(receipt), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "protected entity"):
                wp3_runtime.read_migration_approval(root, FIXTURE_CONTROL_PLANE_ID, role_values)

    def test_migration_approval_reader_rejects_duplicate_keys_symlinks_and_unsafe_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, _report, _receipt, path = prepare_migration_root(root)
            raw = path.read_text(encoding="utf-8")
            path.write_text(raw.replace('"approved": true,', '"approved": true, "approved": true,', 1))
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "duplicate receipt field"):
                wp3_runtime.read_migration_approval(root, FIXTURE_CONTROL_PLANE_ID, role_values)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, _report, _receipt, path = prepare_migration_root(root)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode-0600"):
                wp3_runtime.read_migration_approval(root, FIXTURE_CONTROL_PLANE_ID, role_values)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, _report, _receipt, path = prepare_migration_root(root)
            target = path.with_name("private-target.json")
            path.replace(target)
            path.symlink_to(target.name)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                wp3_runtime.read_migration_approval(root, FIXTURE_CONTROL_PLANE_ID, role_values)

    def test_launcher_rejects_invalid_approval_before_token_or_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, _report, receipt, path = prepare_migration_root(root)
            receipt["approved"] = False
            path.write_text(json.dumps(receipt), encoding="utf-8")
            path.chmod(0o600)
            (root / ".generated/runtime-api.json").write_text(json.dumps(role_values), encoding="utf-8")
            calls = []
            with patch.object(run_deck, "local_manifest", return_value=fake_target_info()), patch.object(
                run_deck, "validate_role_values", side_effect=lambda _gateway, values: values
            ), patch.object(run_deck, "read_env", side_effect=AssertionError("token read reached")) as read_env, patch.object(
                run_deck, "verify_remote_target", side_effect=lambda *args: calls.append("target")
            ), patch.object(run_deck, "verify_shared_api_ca", side_effect=lambda *args: calls.append("ca")), patch.object(
                run_deck, "check_schemas", side_effect=lambda *args: calls.append("schemas")
            ), patch.object(run_deck.subprocess, "run", side_effect=lambda *args, **kwargs: calls.append("subprocess")), patch.object(
                sys, "argv", ["run-deck.py", "sync", "--root", str(root), "--gateway", "api", "--stage", "runtime"]
            ), patch.dict(os.environ, {"WP3_API_RUNTIME_MIGRATION_APPROVED": "YES"}):
                with self.assertRaisesRegex(ValueError, "target and scope"):
                    run_deck.main()
            read_env.assert_not_called()
            self.assertEqual(calls, [])

    def test_launcher_source_or_role_drift_fails_before_token_or_network(self):
        for drift in ("source", "role"):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                role_values, _report, _receipt, _path = prepare_migration_root(root)
                role_file = root / ".generated/runtime-api.json"
                role_file.write_text(json.dumps(role_values), encoding="utf-8")
                if drift == "source":
                    (root / "kong/api-gateway.yaml").write_text("stale fixture source\n")
                else:
                    changed = {**role_values, "API_INTROSPECTION_KEY": "stale fixture role"}
                    role_file.write_text(json.dumps(changed), encoding="utf-8")
                calls = []
                with patch.object(run_deck, "local_manifest", return_value=fake_target_info()), patch.object(
                    run_deck, "validate_role_values", side_effect=lambda _gateway, values: values
                ), patch.object(run_deck, "read_env", side_effect=AssertionError("token read reached")) as read_env, patch.object(
                    run_deck, "verify_remote_target", side_effect=lambda *args: calls.append("target")
                ), patch.object(run_deck, "verify_shared_api_ca", side_effect=lambda *args: calls.append("ca")), patch.object(
                    run_deck, "check_schemas", side_effect=lambda *args: calls.append("schemas")
                ), patch.object(run_deck.subprocess, "run", side_effect=lambda *args, **kwargs: calls.append("subprocess")), patch.object(
                    sys, "argv", ["run-deck.py", "sync", "--root", str(root), "--gateway", "api", "--stage", "runtime"]
                ), patch.dict(os.environ, {"WP3_API_RUNTIME_MIGRATION_APPROVED": "YES"}):
                    with self.assertRaisesRegex(ValueError, "current runtime state|certificate role inputs"):
                        run_deck.main()
                read_env.assert_not_called()
                self.assertEqual(calls, [])

    def test_launcher_rejects_role_file_symlink_or_wrong_mode_before_token(self):
        for unsafe in ("symlink", "mode"):
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                role_values, _report, _receipt, _path = prepare_migration_root(root)
                role_path = root / ".generated/runtime-api.json"
                if unsafe == "symlink":
                    target = root / ".generated/other-role.json"
                    role_path.replace(target)
                    role_path.symlink_to(target.name)
                else:
                    role_path.chmod(0o644)
                calls = []
                with patch.object(run_deck, "local_manifest", return_value=fake_target_info()), patch.object(
                    run_deck, "read_env", side_effect=AssertionError("token read reached")
                ) as read_env, patch.object(run_deck, "verify_remote_target", side_effect=lambda *args: calls.append("target")), patch.object(
                    run_deck, "verify_shared_api_ca", side_effect=lambda *args: calls.append("ca")
                ), patch.object(run_deck, "check_schemas", side_effect=lambda *args: calls.append("schemas")), patch.object(
                    run_deck.subprocess, "run", side_effect=lambda *args, **kwargs: calls.append("subprocess")
                ), patch.object(
                    sys, "argv", ["run-deck.py", "sync", "--root", str(root), "--gateway", "api", "--stage", "runtime"]
                ), patch.dict(os.environ, {"WP3_API_RUNTIME_MIGRATION_APPROVED": "YES"}):
                    with self.assertRaisesRegex(ValueError, "role-scoped decK input"):
                        run_deck.main()
                read_env.assert_not_called()
                self.assertEqual(calls, [])

    def test_launcher_requires_separate_migration_environment_gate_before_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, _report, _receipt, _path = prepare_migration_root(root)
            (root / ".generated/runtime-api.json").write_text(json.dumps(role_values), encoding="utf-8")
            with patch.object(run_deck, "local_manifest", return_value=fake_target_info()), patch.object(
                run_deck, "validate_role_values", side_effect=lambda _gateway, values: values
            ), patch.object(run_deck, "read_env", side_effect=AssertionError("token read reached")) as read_env, patch.object(
                sys, "argv", ["run-deck.py", "sync", "--root", str(root), "--gateway", "api", "--stage", "runtime"]
            ), patch.dict(os.environ, {"WP3_API_RUNTIME_MIGRATION_APPROVED": "NO"}):
                with self.assertRaisesRegex(ValueError, "separate live migration"):
                    run_deck.main()
            read_env.assert_not_called()

    def test_launcher_valid_approval_uses_token_environment_and_single_sync(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, report, _receipt, _path = prepare_migration_root(root)
            (root / ".generated/runtime-api.json").write_text(json.dumps(role_values), encoding="utf-8")
            token = "offline-fixture-token-sentinel"
            calls = []

            def deck_run(command, **kwargs):
                calls.append((command, kwargs))
                if command[2] == "diff":
                    return subprocess.CompletedProcess(command, 0, stdout=json.dumps(report), stderr="")
                return subprocess.CompletedProcess(command, 0, stdout="offline-sync-success", stderr="")

            def read_env(path):
                return {"KONNECT_TOKEN": token} if path.name == ".env" else {}

            stdout = io.StringIO()
            with patch.object(run_deck, "local_manifest", return_value=fake_target_info()), patch.object(
                run_deck, "validate_role_values", side_effect=lambda _gateway, values: values
            ), patch.object(run_deck, "read_env", side_effect=read_env), patch.object(
                run_deck, "verify_remote_target", return_value=None
            ), patch.object(run_deck, "verify_shared_api_ca", return_value=None), patch.object(
                run_deck, "check_schemas", return_value=None
            ), patch.object(run_deck.subprocess, "run", side_effect=deck_run), patch.object(
                sys, "argv", ["run-deck.py", "sync", "--root", str(root), "--gateway", "api", "--stage", "runtime"]
            ), patch.dict(os.environ, {"WP3_API_RUNTIME_MIGRATION_APPROVED": "YES"}), contextlib.redirect_stdout(stdout):
                result = run_deck.main()
            self.assertEqual(result, 0)
            self.assertEqual([call[0][2] for call in calls], ["diff", "sync"])
            for command, kwargs in calls:
                self.assertNotIn("--konnect-token", command)
                self.assertNotIn(token, command)
                self.assertEqual(kwargs["env"].get("DECK_KONNECT_TOKEN"), token)
                self.assertNotIn("KONNECT_TOKEN", kwargs["env"])
                self.assertEqual(kwargs["timeout"], run_deck.DECK_SUBPROCESS_TIMEOUT_SECONDS)
            self.assertIn("offline-sync-success", stdout.getvalue())
            self.assertNotIn(token, stdout.getvalue())

    def test_launcher_diff_diagnostics_and_digest_mismatch_never_sync(self):
        for stderr, mutate_report in (("diagnostic-sentinel", False), ("", True)):
            with self.subTest(stderr=bool(stderr), mutate=mutate_report), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                role_values, report, _receipt, _path = prepare_migration_root(root)
                (root / ".generated/runtime-api.json").write_text(json.dumps(role_values), encoding="utf-8")
                observed = copy.deepcopy(report)
                if mutate_report:
                    observed["changes"]["deleting"][0]["body"]["new"]["protocol"] = "http"
                calls = []

                def deck_run(command, **kwargs):
                    calls.append(command)
                    return subprocess.CompletedProcess(command, 0, stdout=json.dumps(observed), stderr=stderr)

                def read_env(path):
                    return {"KONNECT_TOKEN": "offline-token"} if path.name == ".env" else {}

                stdout = io.StringIO()
                with patch.object(run_deck, "local_manifest", return_value=fake_target_info()), patch.object(
                    run_deck, "validate_role_values", side_effect=lambda _gateway, values: values
                ), patch.object(run_deck, "read_env", side_effect=read_env), patch.object(
                    run_deck, "verify_remote_target", return_value=None
                ), patch.object(run_deck, "verify_shared_api_ca", return_value=None), patch.object(
                    run_deck, "check_schemas", return_value=None
                ), patch.object(run_deck.subprocess, "run", side_effect=deck_run), patch.object(
                    sys, "argv", ["run-deck.py", "sync", "--root", str(root), "--gateway", "api", "--stage", "runtime"]
                ), patch.dict(os.environ, {"WP3_API_RUNTIME_MIGRATION_APPROVED": "YES"}), contextlib.redirect_stdout(stdout):
                    with self.assertRaises(ValueError):
                        run_deck.main()
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0][2], "diff")
                self.assertNotIn("WP3_MIGRATION_DIFF_SHA256", stdout.getvalue())
                self.assertNotIn("diagnostic-sentinel", stdout.getvalue())

    def test_launcher_rechecks_source_role_after_read_only_diff(self):
        for drift in ("source", "role"):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                role_values, report, _receipt, _path = prepare_migration_root(root)
                role_file = root / ".generated/runtime-api.json"
                role_file.write_text(json.dumps(role_values), encoding="utf-8")
                calls = []

                def deck_run(command, **kwargs):
                    calls.append(command)
                    if drift == "source":
                        (root / "kong/api-gateway.yaml").write_text("raced source\n")
                    else:
                        altered = {**role_values, "API_INTROSPECTION_KEY": "raced-role"}
                        role_file.write_text(json.dumps(altered), encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, stdout=json.dumps(report), stderr="")

                def read_env(path):
                    return {"KONNECT_TOKEN": "offline-token"} if path.name == ".env" else {}

                with patch.object(run_deck, "local_manifest", return_value=fake_target_info()), patch.object(
                    run_deck, "validate_role_values", side_effect=lambda _gateway, values: values
                ), patch.object(run_deck, "read_env", side_effect=read_env), patch.object(
                    run_deck, "verify_remote_target", return_value=None
                ), patch.object(run_deck, "verify_shared_api_ca", return_value=None), patch.object(
                    run_deck, "check_schemas", return_value=None
                ), patch.object(run_deck.subprocess, "run", side_effect=deck_run), patch.object(
                    sys, "argv", ["run-deck.py", "sync", "--root", str(root), "--gateway", "api", "--stage", "runtime"]
                ), patch.dict(os.environ, {"WP3_API_RUNTIME_MIGRATION_APPROVED": "YES"}):
                    with self.assertRaisesRegex(ValueError, "changed after approval"):
                        run_deck.main()
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0][2], "diff")

    def test_launcher_sync_timeout_or_nonzero_is_unknown_and_not_retried(self):
        for failure in ("timeout", "nonzero"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                role_values, report, _receipt, _path = prepare_migration_root(root)
                (root / ".generated/runtime-api.json").write_text(json.dumps(role_values), encoding="utf-8")
                token = "timeout-fixture-token-sentinel"
                calls = []

                def deck_run(command, **kwargs):
                    calls.append(command)
                    if command[2] == "diff":
                        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(report), stderr="")
                    if failure == "timeout":
                        raise subprocess.TimeoutExpired(command, 300, output=token, stderr="raw-diagnostic-sentinel")
                    return subprocess.CompletedProcess(command, 2, stdout=token, stderr="raw-diagnostic-sentinel")

                def read_env(path):
                    return {"KONNECT_TOKEN": token} if path.name == ".env" else {}

                output = io.StringIO()
                with patch.object(run_deck, "local_manifest", return_value=fake_target_info()), patch.object(
                    run_deck, "validate_role_values", side_effect=lambda _gateway, values: values
                ), patch.object(run_deck, "read_env", side_effect=read_env), patch.object(
                    run_deck, "verify_remote_target", return_value=None
                ), patch.object(run_deck, "verify_shared_api_ca", return_value=None), patch.object(
                    run_deck, "check_schemas", return_value=None
                ), patch.object(run_deck.subprocess, "run", side_effect=deck_run), patch.object(
                    sys, "argv", ["run-deck.py", "sync", "--root", str(root), "--gateway", "api", "--stage", "runtime"]
                ), patch.dict(os.environ, {"WP3_API_RUNTIME_MIGRATION_APPROVED": "YES"}), contextlib.redirect_stdout(output):
                    with self.assertRaisesRegex(ValueError, "outcome is unknown") as error:
                        run_deck.main()
                self.assertEqual(len(calls), 2)
                self.assertNotIn(token, str(error.exception))
                self.assertNotIn("raw-diagnostic-sentinel", str(error.exception))
                self.assertNotIn(token, output.getvalue())
                self.assertNotIn("raw-diagnostic-sentinel", output.getvalue())

    def test_launcher_pre_sync_diff_timeout_is_safe_and_never_syncs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, _report, _receipt, _path = prepare_migration_root(root)
            (root / ".generated/runtime-api.json").write_text(json.dumps(role_values), encoding="utf-8")
            calls = []
            token = "pre-sync-timeout-token-sentinel"

            def deck_run(command, **kwargs):
                calls.append(command)
                raise subprocess.TimeoutExpired(command, run_deck.DECK_SUBPROCESS_TIMEOUT_SECONDS, output=token, stderr="private-timeout-output")

            def read_env(path):
                return {"KONNECT_TOKEN": token} if path.name == ".env" else {}

            output = io.StringIO()
            with patch.object(run_deck, "local_manifest", return_value=fake_target_info()), patch.object(
                run_deck, "validate_role_values", side_effect=lambda _gateway, values: values
            ), patch.object(run_deck, "read_env", side_effect=read_env), patch.object(
                run_deck, "verify_remote_target", return_value=None
            ), patch.object(run_deck, "verify_shared_api_ca", return_value=None), patch.object(
                run_deck, "check_schemas", return_value=None
            ), patch.object(run_deck.subprocess, "run", side_effect=deck_run), patch.object(
                sys, "argv", ["run-deck.py", "sync", "--root", str(root), "--gateway", "api", "--stage", "runtime"]
            ), patch.dict(os.environ, {"WP3_API_RUNTIME_MIGRATION_APPROVED": "YES"}), contextlib.redirect_stdout(output):
                with self.assertRaisesRegex(ValueError, "sync was not attempted") as error:
                    run_deck.main()
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][2], "diff")
            self.assertNotIn(token, str(error.exception))
            self.assertNotIn("private-timeout-output", str(error.exception))
            self.assertNotIn(token, output.getvalue())
            self.assertNotIn("private-timeout-output", output.getvalue())

    def test_launcher_runtime_diff_rejects_diagnostics_before_publishing_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            role_values, report, _receipt, _path = prepare_migration_root(root)
            (root / ".generated/runtime-api.json").write_text(json.dumps(role_values), encoding="utf-8")
            command_calls = []

            def deck_run(command, **kwargs):
                command_calls.append(command)
                return subprocess.CompletedProcess(command, 0, stdout=json.dumps(report), stderr="unsafe diagnostic sentinel")

            def read_env(path):
                return {"KONNECT_TOKEN": "offline-token"} if path.name == ".env" else {}

            stdout = io.StringIO()
            with patch.object(run_deck, "local_manifest", return_value=fake_target_info()), patch.object(
                run_deck, "validate_role_values", side_effect=lambda _gateway, values: values
            ), patch.object(run_deck, "read_env", side_effect=read_env), patch.object(
                run_deck, "verify_remote_target", return_value=None
            ), patch.object(run_deck, "verify_shared_api_ca", return_value=None), patch.object(
                run_deck, "check_schemas", return_value=None
            ), patch.object(run_deck.subprocess, "run", side_effect=deck_run), patch.object(
                sys, "argv", ["run-deck.py", "diff", "--root", str(root), "--gateway", "api", "--stage", "runtime"]
            ), contextlib.redirect_stdout(stdout):
                with self.assertRaisesRegex(ValueError, "unexpected diagnostics"):
                    run_deck.main()
            self.assertEqual(len(command_calls), 1)
            self.assertNotIn("WP3_MIGRATION_DIFF_SHA256", stdout.getvalue())
            self.assertNotIn("unsafe diagnostic sentinel", stdout.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
