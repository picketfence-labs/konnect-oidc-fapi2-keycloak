#!/usr/bin/env python3
"""Focused source-contract and patcher tests for the WP5 Keycloak observer spike."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OBSERVER = ROOT / "tests/harness/wp5_observer/observer/AsPeerObserver.java"
PATCHER = ROOT / "tests/harness/wp5_observer/patch_keycloak_source.py"
ANCHOR = b"        KeycloakSessionUtil.setKeycloakSession(currentSession);\n"
CALL = b"        AsPeerObserver.observe(currentSession);\n"


def load_patcher():
    spec = importlib.util.spec_from_file_location("wp5_patcher_test", PATCHER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ObserverSourceContractTests(unittest.TestCase):
    def test_flag_off_returns_before_request_or_peer_reads(self):
        source = OBSERVER.read_text(encoding="utf-8")
        off_guard = 'if (!"true".equals(System.getenv(ENABLED_ENV)))'
        self.assertIn(off_guard, source)
        self.assertLess(source.index(off_guard), source.index("CDI.current()"))
        self.assertLess(source.index(off_guard), source.index("session.getContext()"))
        self.assertLess(source.index(off_guard), source.index("getRequestHeader("))
        self.assertLess(source.index(off_guard), source.index("getClientCertificateChain()"))

    def test_request_marker_precedes_request_processing_and_is_request_local(self):
        source = OBSERVER.read_text(encoding="utf-8")
        marker = "routingContext.put(REQUEST_MARKER, Boolean.TRUE);"
        self.assertIn("routingContext.get(REQUEST_MARKER)", source)
        self.assertIn("RoutingContext routingContext", source)
        self.assertNotIn("ThreadLocal", source)
        self.assertNotIn("static Map", source)
        self.assertLess(source.index(marker), source.index("session.getContext()"))
        self.assertLess(source.index(marker), source.index("routingContext.request().path()"))
        self.assertIn("catch (RuntimeException ignored)", source)
        self.assertIn("catch (Exception ignored)", source)

    def test_observer_reads_only_fixed_inventory_and_correlation_header(self):
        source = OBSERVER.read_text(encoding="utf-8")
        for endpoint in (
            '"discovery"',
            '"jwks"',
            '"par"',
            '"token"',
            '"revoke"',
        ):
            self.assertIn(endpoint, source)
        self.assertIn('"X-Fapi-Demo-Observation-ID"', source)
        self.assertIn('"[0-9a-f]{32}"', source)
        self.assertIn("canonicalPath(routingContext.request().path())", source)
        self.assertNotIn("getPath(false)", source)
        self.assertNotIn("getPath(true)", source)
        self.assertNotIn("getQueryParameters", source)
        self.assertNotIn("getRequestUri", source)
        for raw_path in (
            '"/realms/fapi-demo/.well-known/openid-configuration"',
            '"/realms/fapi-demo/protocol/openid-connect/certs"',
            '"/realms/fapi-demo/protocol/openid-connect/ext/par/request"',
            '"/realms/fapi-demo/protocol/openid-connect/token"',
            '"/realms/fapi-demo/protocol/openid-connect/revoke"',
        ):
            self.assertIn(raw_path, source)
        for forbidden in (
            "getDecodedFormParameters",
            "getMultiPartFormParameters",
            "getRequestHeaders()",
            "getHeaderString(",
            "getBody(",
            '"Authorization"',
            '"Cookie"',
            "printStackTrace",
            "getMessage()",
        ):
            self.assertNotIn(forbidden, source)

    def test_log_uses_fixed_fields_and_never_serializes_exception_or_certificate_text(self):
        source = OBSERVER.read_text(encoding="utf-8")
        self.assertIn("WP5_AS_PEER_OBS v=1", source)
        self.assertIn("observed_at=%s", source)
        self.assertIn("method=%s path=%s", source)
        for forbidden in (
            "getSubjectX500Principal",
            "getIssuerX500Principal",
            "getEncoded()\"",
            "certificate.toString()",
            "LOG.error",
            "LOG.warn",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("CertPathValidator.getInstance(\"PKIX\")", source)
        self.assertIn('"1.3.6.1.5.5.7.3.2"', source)
        self.assertIn("certificate.checkValidity()", source)
        self.assertIn("return null;", source[source.index("static String canonicalPath"):source.index("static String endpoint")])
        self.assertLess(source.index("if (candidateEndpoint == null)"), source.index("observedMethod = candidateMethod;"))
        self.assertLess(source.index("observedMethod = candidateMethod;"), source.index("correlation = correlationId("))


class SourcePatcherTests(unittest.TestCase):
    def test_anchored_patch_inserts_once_after_session_context(self):
        patcher = load_patcher()
        source = b"before\n" + ANCHOR + b"        super.handle(requestContext);\n"
        patched = patcher.patch_handler_bytes(source, hashlib.sha256(source).hexdigest())
        self.assertEqual(patched.count(CALL), 1)
        self.assertLess(patched.index(ANCHOR), patched.index(CALL))
        self.assertLess(patched.index(CALL), patched.index(b"super.handle(requestContext);"))

    def test_patcher_rejects_source_drift_duplicates_and_repeat_application(self):
        patcher = load_patcher()
        source = b"before\n" + ANCHOR + b"after\n"
        with self.assertRaises(patcher.PatchError) as drift:
            patcher.patch_handler_bytes(source, "0" * 64)
        self.assertEqual(drift.exception.reason, "handler_source_digest_mismatch")

        duplicated = source + ANCHOR
        with self.assertRaises(patcher.PatchError) as duplicate:
            patcher.patch_handler_bytes(duplicated, hashlib.sha256(duplicated).hexdigest())
        self.assertEqual(duplicate.exception.reason, "handler_anchor_count_mismatch")

        patched = patcher.patch_handler_bytes(source, hashlib.sha256(source).hexdigest())
        with self.assertRaises(patcher.PatchError) as repeat:
            patcher.patch_handler_bytes(patched, hashlib.sha256(patched).hexdigest())
        self.assertEqual(repeat.exception.reason, "handler_already_patched")

    def test_source_tree_patch_is_bound_to_clean_checkout_and_changes_only_two_files(self):
        patcher = load_patcher()
        with tempfile.TemporaryDirectory(prefix="wp5-patcher-test-") as temporary:
            source_tree = Path(temporary) / "source"
            source_tree.mkdir()
            subprocess.run(["git", "init", "-q", str(source_tree)], check=True)
            relative = patcher.HANDLER_RELATIVE
            handler = source_tree / relative
            handler.parent.mkdir(parents=True)
            original = b"before\n" + ANCHOR + b"        super.handle(requestContext);\n"
            handler.write_bytes(original)
            subprocess.run(["git", "-C", str(source_tree), "add", str(relative)], check=True)
            env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "WP5 test",
                "GIT_AUTHOR_EMAIL": "wp5-test@example.invalid",
                "GIT_COMMITTER_NAME": "WP5 test",
                "GIT_COMMITTER_EMAIL": "wp5-test@example.invalid",
            }
            subprocess.run(
                ["git", "-C", str(source_tree), "commit", "-qm", "fixture"],
                check=True,
                env=env,
            )
            commit = subprocess.run(
                ["git", "-C", str(source_tree), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            helper = Path(temporary) / "AsPeerObserver.java"
            helper.write_bytes(b"package example; final class AsPeerObserver {}\n")

            old_commit, old_hash = patcher.PINNED_COMMIT, patcher.PINNED_HANDLER_SHA256
            try:
                patcher.PINNED_COMMIT = commit
                patcher.PINNED_HANDLER_SHA256 = hashlib.sha256(original).hexdigest()
                result = patcher.apply_source_tree(source_tree, helper)
            finally:
                patcher.PINNED_COMMIT, patcher.PINNED_HANDLER_SHA256 = old_commit, old_hash

            self.assertEqual(result["changed_file_count"], "2")
            self.assertIn(CALL, handler.read_bytes())
            self.assertTrue((handler.parent / "AsPeerObserver.java").is_file())
            status = subprocess.run(
                ["git", "-C", str(source_tree), "status", "--porcelain", "--untracked-files=all"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()
            self.assertEqual(len(status), 2)
            self.assertEqual(
                {line[3:] for line in status},
                {str(relative), str(relative.parent / "AsPeerObserver.java")},
            )


if __name__ == "__main__":
    unittest.main()
