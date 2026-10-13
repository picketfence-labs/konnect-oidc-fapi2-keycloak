#!/usr/bin/env python3
"""Offline routing, deployment identity and versioned approval contracts."""

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests import test_wp5_deck_selector as selector
from tests import test_wp5_runtime as runtime_tests
from tests import test_third_party_backend as backend_tests
target = selector.wp1_target
deck = selector.run_deck


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="backend-integration-")
        self.root = Path(self.temp.name)
        selector.fixture_tree(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_each_as_service_static_identity_conjunct_and_last_identity(self):
        path = self.root / "kong/third-party-gateway.yaml"
        source = path.read_text()
        original = target._parse_foundation(path)
        mutations = [
            lambda s: s["services"][0].update(host="kong-api"),
            lambda s: s["services"][0].update(port=8443),
            lambda s: s["services"][0].update(path="/evidence/route-b"),
            lambda s: s["services"][0].update(tls_verify=False),
            lambda s: s["services"][0].update(ca_certificates=[]),
            lambda s: s["services"][0].update(client_certificate="11111111-1111-4111-8111-111111111111"),
            lambda s: s["services"][0]["plugins"][1]["config"].update(tls_client_auth_cert_id="742c3d79-850f-5761-9544-63864bab5cad"),
            lambda s: s["plugins"][0]["config"]["routes"][0].update(certificate_file="/etc/kong/fapi/hop.crt"),
            lambda s: s["services"][1]["plugins"][1]["config"].update(tls_certificate_file="/etc/kong/fapi/hop.crt"),
            lambda s: s["certificates"][-1].update(key="{vault://env/ROUTE_A_TLS_KEY}"),
            lambda s: s["services"][-1]["routes"][0].update(paths=["/"]),
            lambda s: s["services"][-1]["plugins"][0]["config"]["remove"].update(headers=["Cookie"]),
            lambda s: s["services"][-1]["plugins"].append({"name": "openid-connect"}),
        ]
        for service_index in (0, 1):
            for plugin_index in range(len(original["services"][service_index]["plugins"])):
                mutations.append(lambda value, si=service_index, pi=plugin_index:
                                 value["services"][si]["plugins"][pi].update(enabled=False))
        for mutate in mutations:
            value = copy.deepcopy(original)
            mutate(value)
            path.write_text(yaml.safe_dump(value, sort_keys=False))
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                target.validate_third_party_runtime_state(self.root)
        path.write_text(source)
        target.validate_third_party_runtime_state(self.root)

    def test_declared_mounts_and_container_user_are_exact(self):
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
        backend = compose["services"]["third-party-backend"]
        self.assertNotIn("ports", backend)
        self.assertNotIn("env_file", backend)
        mounts = backend["volumes"]
        expected = {
            "ca.crt": "ca.crt", "third-party-backend.crt": "tls.crt", "third-party-backend.key": "tls.key",
            "third-party-backend-hop.crt": "third-party-backend-hop.crt", "route-a.crt": "route-a.crt",
            "route-a.key": "route-a.key", "route-b.crt": "route-b.crt", "route-b.key": "route-b.key",
        }
        self.assertEqual(set(mounts), {f"./.generated/pki/{source}:/etc/fapi/{destination}:ro" for source, destination in expected.items()})
        self.assertEqual(backend["tmpfs"], ["/run/fapi:uid=1000,gid=1000,mode=0700"])
        dockerfile = (ROOT / "third-party-backend/Dockerfile").read_text()
        self.assertIn("addgroup -S -g 1000 backend", dockerfile)
        self.assertIn("adduser -S -u 1000 -G backend backend", dockerfile)
        self.assertIn("USER backend", dockerfile)
        self.assertEqual(backend["healthcheck"]["test"], ["CMD", "python", "-B", "/app/app.py", "--check-ready"])
        native = (ROOT / "docker-compose.demo-native.yml").read_text().split("  third-party-backend:")[1]
        self.assertIn('user: "1000:1000"', native)
        self.assertIn("./third-party-backend/app.py:/app/app.py:ro", native)
        self.assertNotIn("ports", compose["services"]["ui"])
        self.assertIn("access_log off", (ROOT / "ui/default.conf").read_text())

    def test_exact_plan_scopes_reject_late_invalid_operations(self):
        for plan_type, expected in deck.BACKEND_PLANS.items():
            operations = {op: [{"kind": kind, "name": name} for kind, name in sorted(entries)] for op, entries in expected.items()}
            summary = {op: len(entries) for op, entries in operations.items()}
            summary["total"] = sum(summary.values())
            value = {"summary": summary, "operations": operations}
            deck.validate_backend_scope(value, plan_type)
            bad = copy.deepcopy(value)
            bad["operations"]["deleting"].append({"kind": "service", "name": "foreign-last"})
            with self.assertRaises(ValueError):
                deck.validate_backend_scope(bad, plan_type)
            if plan_type != "noop":
                bad = copy.deepcopy(value)
                bad["operations"]["creating"][-1]["name"] = "foreign-last"
                with self.assertRaises(ValueError):
                    deck.validate_backend_scope(bad, plan_type)
            bad = copy.deepcopy(value)
            bad["summary"]["deleting"] = False
            with self.assertRaises(ValueError):
                deck.validate_backend_scope(bad, plan_type)

    def test_old_receipt_and_late_invalid_schema_cannot_read_token_or_sync(self):
        receipt = selector.write_wp5_receipt(self.root, selector.additive_report())
        path = self.root / deck.BACKEND_APPROVAL_RELATIVE
        for change in ({"schema_version": 1, "scope": "third-party-runtime"}, {"approved": 1}, {"plan_type": "arbitrary"},
                       {"role_inputs_sha256": "0" * 64}, {"diff_sha256": "invalid"}):
            path.write_text(json.dumps({**receipt, **change}))
            with patch.object(sys, "argv", ["run-deck.py", "sync", "--root", str(self.root), "--gateway", "third-party", "--stage", "runtime"]), \
                 patch.dict(os.environ, {"TP_BACKEND_RUNTIME_V2_APPROVED": "YES"}), \
                 patch.object(deck, "read_env", side_effect=AssertionError("token read")), \
                 patch.object(deck, "verify_remote_target") as remote, patch.object(deck, "run_deck_subprocess") as invoke:
                with self.assertRaises(ValueError):
                    deck.main()
                remote.assert_not_called()
                invoke.assert_not_called()

    def test_receipt_replaced_during_pre_sync_diff_prevents_sync(self):
        report = selector.additive_report()
        receipt = selector.write_wp5_receipt(self.root, report)
        calls = []

        def fake_deck(command, **kwargs):
            calls.append(command[2])
            self.assertEqual(command[2], "diff", "a changed receipt must prevent sync")
            path = self.root / deck.BACKEND_APPROVAL_RELATIVE
            path.write_text(json.dumps({**receipt, "diff_sha256": "0" * 64}))
            return subprocess.CompletedProcess(command, 0, json.dumps(report), "")

        with patch.object(sys, "argv", ["run-deck.py", "sync", "--root", str(self.root), "--gateway", "third-party", "--stage", "runtime"]), \
             patch.dict(os.environ, {"TP_BACKEND_RUNTIME_V2_APPROVED": "YES"}), \
             patch.object(deck, "verify_remote_target"), patch.object(deck, "check_schemas"), \
             patch.object(deck, "run_deck_subprocess", side_effect=fake_deck):
            with self.assertRaisesRegex(ValueError, "changed after review; sync was not attempted"):
                deck.main()
        self.assertEqual(calls, ["diff"])

    def test_real_cli_old_flag_has_zero_token_remote_and_deck_calls(self):
        # Only external auth/network/decK boundaries are replaced. The original
        # argument parsing, source validation, flag and approval gates execute.
        script = '''import importlib.util,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location("runner",sys.argv[1]); m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def forbidden(*args,**kwargs):
    print("FORBIDDEN_BOUNDARY"); raise AssertionError("token/network/deck boundary")
m.read_env=forbidden;m.verify_remote_target=forbidden;m.run_deck_subprocess=forbidden
sys.argv=[sys.argv[1],"sync","--root",sys.argv[2],"--gateway","third-party","--stage","runtime"]
try: m.main()
except ValueError as error: print(str(error));sys.exit(7)
'''
        env = {**os.environ, "WP5_THIRD_PARTY_RUNTIME_APPROVED": "YES", "TP_BACKEND_RUNTIME_V2_APPROVED": "NO"}
        result = subprocess.run([sys.executable, "-B", "-c", script, str(ROOT / "scripts/run-deck.py"), str(self.root)],
                                env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("TP_BACKEND_RUNTIME_V2_APPROVED=YES", result.stdout)
        self.assertNotIn("FORBIDDEN_BOUNDARY", result.stdout + result.stderr)


class IntegrationMutations(unittest.TestCase):
    def assert_killed(self, case):
        result = unittest.TestResult()
        unittest.TestSuite([case]).run(result)
        self.assertEqual(result.errors, [], "mutation must fail by a contract assertion, not a fixture error")
        self.assertTrue(result.failures, "semantic mutation survived")

    def test_phase2_semantic_mutations(self):
        cases = (
            ("service_identity_conjunct", "scripts/wp1_target.py",
             "or any(service.get(name) != value for name, value in expected_service.items())",
             'or any(service.get(name) != value for name, value in expected_service.items() if name != "client_certificate")',
             "target", IntegrationTests, "test_each_as_service_static_identity_conjunct_and_last_identity"),
            ("late_operation_identity", "scripts/run-deck.py",
             "or set(identities) != expected[operation]", "",
             "deck", IntegrationTests, "test_exact_plan_scopes_reject_late_invalid_operations"),
            ("old_receipt_rejected_before_token", "scripts/run-deck.py",
             'receipt["scope"] != BACKEND_SCOPE', 'receipt["scope"] not in (BACKEND_SCOPE,"third-party-runtime")',
             "deck", IntegrationTests, "test_old_receipt_and_late_invalid_schema_cannot_read_token_or_sync"),
        )
        for name, file, before, after, binding, test_class, method in cases:
            with self.subTest(property=name):
                source = (ROOT / file).read_text()
                self.assertEqual(source.count(before), 1)
                changed = source.replace(before, after)
                if name == "old_receipt_rejected_before_token":
                    changed = changed.replace('receipt["schema_version"] != 2', 'receipt["schema_version"] not in (1,2)')
                mutant = types.ModuleType("integration_mutant_" + name)
                mutant.__file__ = str(ROOT / file)
                sys.modules[mutant.__name__] = mutant
                original = globals()[binding]
                try:
                    exec(compile(changed, mutant.__file__, "exec"), mutant.__dict__)
                    globals()[binding] = mutant
                    self.assert_killed(test_class(method))
                    print("phase2 semantic mutation killed:", name)
                finally:
                    globals()[binding] = original
                    del sys.modules[mutant.__name__]
        for name, file, before, after, case in (
            ("backend_failure_blocks_forward", "scripts/require-wp5-readiness.sh", "check_backend_once() {", "check_backend_once() {\n  return 0",
             runtime_tests.ThirdPartyRuntimeTests("test_backend_failure_never_opens_public_forward")),
            ("declared_private_mounts", "docker-compose.yml", "      - ./.generated/pki/route-b.key:/etc/fapi/route-b.key:ro\n", "",
             IntegrationTests("test_declared_mounts_and_container_user_are_exact")),
        ):
            with self.subTest(property=name):
                path = ROOT / file
                original_read = Path.read_text
                source = original_read(path)
                self.assertEqual(source.count(before), 1)
                changed = source.replace(before, after)
                def read(candidate, *args, **kwargs):
                    return changed if candidate == path else original_read(candidate, *args, **kwargs)
                with patch.object(Path, "read_text", read):
                    self.assert_killed(case)
                print("phase2 semantic mutation killed:", name)
        # The actual Unix IPC public test catches skipping the late key validation.
        name = "unix_ready_revalidates_last_identity"
        source = (ROOT / "third-party-backend/app.py").read_text()
        before = "create_contexts(self.server.files)"
        self.assertEqual(source.count(before), 1)
        mutant = types.ModuleType("integration_mutant_ready")
        sys.modules[mutant.__name__] = mutant
        try:
            exec(compile(source.replace(before, "pass"), str(ROOT / "third-party-backend/app.py"), "exec"), mutant.__dict__)
            with patch.object(backend_tests, "app", mutant):
                self.assert_killed(backend_tests.TLSContractTests("test_private_unix_readiness_requires_live_loaded_configuration"))
            print("phase2 semantic mutation killed:", name)
        finally:
            del sys.modules[mutant.__name__]


if __name__ == "__main__":
    unittest.main(verbosity=2)
