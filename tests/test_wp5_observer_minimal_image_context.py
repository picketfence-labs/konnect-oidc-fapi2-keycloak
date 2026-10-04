#!/usr/bin/env python3
"""Trust-boundary tests for the WP5 public-only published-JAR build context."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tests/harness/wp5_observer/prepare_minimal_image_context.py"
SPEC = importlib.util.spec_from_file_location("wp5_minimal_context_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CONTEXT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTEXT)


def archive_bytes(name: str = CONTEXT.RUNTIME_ENTRY, body: bytes = b"published-runtime-jar") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, body)
    return buffer.getvalue()


class PublishedArchiveIdentityTests(unittest.TestCase):
    def inspect(self, data: bytes, *, runtime_sha: str | None = None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.zip"
            path.write_bytes(data)
            with mock.patch.object(CONTEXT, "RELEASE_ZIP_SHA256", hashlib.sha256(data).hexdigest()), \
                    mock.patch.object(CONTEXT, "JAR_COUNT", 1), \
                    mock.patch.object(CONTEXT, "RUNTIME_SHA256", runtime_sha or hashlib.sha256(b"published-runtime-jar").hexdigest()):
                return CONTEXT.inspect_release_zip(path)

    def test_exact_runtime_entry_and_count_produce_relative_hash_manifest_rows(self):
        rows, runtime = self.inspect(archive_bytes())
        self.assertEqual(rows, [("lib/main/org.keycloak.keycloak-quarkus-server-26.7.4.jar", hashlib.sha256(runtime).hexdigest())])
        self.assertEqual(runtime, b"published-runtime-jar")

    def test_release_digest_and_runtime_jar_identity_fail_closed(self):
        data = archive_bytes()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.zip"
            path.write_bytes(data)
            with mock.patch.object(CONTEXT, "RELEASE_ZIP_SHA256", "0" * 64):
                with self.assertRaisesRegex(CONTEXT.ContextError, "release_zip_digest_mismatch"):
                    CONTEXT.inspect_release_zip(path)
        with self.assertRaisesRegex(CONTEXT.ContextError, "runtime_jar_identity_mismatch"):
            self.inspect(data, runtime_sha="0" * 64)

    def test_traversal_or_wrong_jar_inventory_is_rejected(self):
        with self.assertRaisesRegex(CONTEXT.ContextError, "release_jar_path_invalid"):
            self.inspect(archive_bytes("keycloak-26.7.4/lib/../escape.jar", b"x"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.zip"
            path.write_bytes(archive_bytes())
            with mock.patch.object(CONTEXT, "RELEASE_ZIP_SHA256", hashlib.sha256(path.read_bytes()).hexdigest()), \
                    mock.patch.object(CONTEXT, "JAR_COUNT", 2):
                with self.assertRaisesRegex(CONTEXT.ContextError, "release_jar_count_mismatch"):
                    CONTEXT.inspect_release_zip(path)


class FreshContextTests(unittest.TestCase):
    def test_preparer_pins_corrected_helper_and_fresh_v3_output(self):
        self.assertEqual(CONTEXT.digest(CONTEXT.HELPER_PATH.read_bytes()), CONTEXT.HELPER_SHA256)
        self.assertTrue(CONTEXT.DEFAULT_OUTPUT.name.endswith("-v3"))

    @staticmethod
    def files():
        return {
            "Dockerfile": b"FROM pinned\n",
            "AsPeerObserver.java": b"public final class AsPeerObserver {}\n",
            "TransactionalSessionHandler.java": b"public final class Handler {}\n",
            "published-classpath.sha256": b"0" * 64 + b"  lib/main/runtime.jar\n",
            "input.sha256": b"0" * 64 + b"  AsPeerObserver.java\n",
            "context-manifest.json": b"{}\n",
            "compile.sh": b"#!/bin/bash\n",
        }

    def test_context_is_exclusive_private_and_has_only_the_fixed_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "attempt"
            context = CONTEXT.write_context(root, self.files())
            self.assertEqual({path.name for path in context.iterdir()}, set(self.files()))
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(context.stat().st_mode), 0o700)
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in context.iterdir()))
            with self.assertRaisesRegex(CONTEXT.ContextError, "output_path_already_exists"):
                CONTEXT.write_context(root, self.files())

    def test_context_rejects_unlisted_repository_or_secret_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            files = self.files()
            files[".env"] = b"never include secrets"
            with self.assertRaisesRegex(CONTEXT.ContextError, "context_allowlist_mismatch"):
                CONTEXT.write_context(Path(directory) / "attempt", files)


if __name__ == "__main__":
    unittest.main()
