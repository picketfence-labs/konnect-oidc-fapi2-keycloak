#!/usr/bin/env python3
"""Bounded, secret-safe regression tests for the WP5 v4 build diagnostics helper."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tests/harness/wp5_observer/build_capture.py"
SPEC = importlib.util.spec_from_file_location("wp5_build_capture_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CAPTURE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CAPTURE
SPEC.loader.exec_module(CAPTURE)


def run_python(source: str) -> list[str]:
    return [sys.executable, "-c", source]


class BoundedOutputTests(unittest.TestCase):
    def test_maven_goal_line_emits_only_pom_whitelisted_project_and_fixed_goal(self):
        secret = "SENSITIVE_TOKEN_SENTINEL_91"
        line = (
            "[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.14.0:compile "
            "(default-compile) on project keycloak-quarkus-server: "
            f"password={secret} URL=https://private.invalid/?token={secret}\n"
        )
        record = CAPTURE.run_bounded_command(
            run_python(f"import sys; sys.stdout.write({line!r}); sys.exit(1)"),
            phase="runtime_module_compile",
            known_projects={"keycloak-quarkus-server"},
            timeout_seconds=5,
        )
        serialized = json.dumps(record, sort_keys=True)
        self.assertEqual(record["status"], "nonzero_exit")
        self.assertEqual(record["project_ids"], ["keycloak-quarkus-server"])
        self.assertEqual(record["goal_categories"], ["compiler"])
        self.assertIn("maven_goal_failure", record["error_categories"])
        self.assertNotIn(secret, serialized)
        self.assertNotIn("private.invalid", serialized)
        self.assertNotIn("default-compile", serialized)
        self.assertFalse(record["raw_output_retained"])

    def test_unknown_project_and_arbitrary_exception_text_are_never_emitted(self):
        secret = "UNKNOWN_PROJECT_SECRET_SENTINEL"
        line = f"[ERROR] Failed to execute goal bad:plugin:1:goal on project {secret}: {secret}\n"
        record = CAPTURE.run_bounded_command(
            run_python(f"import sys; sys.stdout.write({line!r}); sys.exit(1)"),
            phase="runtime_module_compile",
            known_projects={"allowed-project"},
            timeout_seconds=5,
        )
        self.assertEqual(record["project_ids"], [])
        self.assertEqual(record["goal_categories"], [])
        self.assertNotIn(secret, json.dumps(record))

    def test_dns_pkix_and_http_diagnostics_are_fixed_enums_only(self):
        secret_host = "secret-hostname.invalid"
        lines = (
            f"UnknownHostException: {secret_host}\n"
            f"PKIX path building failed for https://{secret_host}/dependency\n"
            f"HTTP/1.1 403 forbidden from https://{secret_host}/repo\n"
        )
        record = CAPTURE.run_bounded_command(
            run_python(f"import sys; sys.stderr.write({lines!r}); sys.exit(1)"),
            phase="runtime_module_compile",
            known_projects=set(),
            timeout_seconds=5,
        )
        self.assertEqual(
            record["error_categories"],
            ["dns_resolution", "http_403", "tls_certificate_validation"],
        )
        self.assertNotIn(secret_host, json.dumps(record))

    def test_total_byte_bound_terminates_and_reports_owned_cleanup(self):
        cleanup_calls: list[bool] = []
        record = CAPTURE.run_bounded_command(
            run_python("import sys; [sys.stdout.write('x'*100+'\\n') for _ in range(100)]"),
            phase="runtime_module_compile",
            known_projects=set(),
            timeout_seconds=5,
            max_total_bytes=1024,
            max_line_bytes=512,
            cleanup_owned=lambda: cleanup_calls.append(True) or "removed",
        )
        self.assertIn(record["status"], {"output_limit", "runner_failure"})
        self.assertEqual(record["output_limit_reason"], "total_bytes")
        self.assertEqual(record["stdout"]["captured_bytes"], 1024)
        self.assertEqual(record["owned_container_cleanup"], "removed")
        self.assertEqual(cleanup_calls, [True])
        if record["status"] == "runner_failure":
            self.assertFalse(record["process_termination_verified"])
            self.assertIn("process_termination_unverified", record["error_categories"])

    def test_line_bound_stops_without_retaining_an_overlong_line(self):
        secret = "OVERLONG_LINE_SENTINEL"
        record = CAPTURE.run_bounded_command(
            run_python(f"import sys; sys.stdout.write(({secret!r}+'x'*200)+'\\n')"),
            phase="runtime_module_compile",
            known_projects=set(),
            timeout_seconds=5,
            max_total_bytes=1024,
            max_line_bytes=64,
        )
        self.assertIn(record["status"], {"output_limit", "runner_failure"})
        self.assertEqual(record["output_limit_reason"], "line_bytes")
        self.assertNotIn(secret, json.dumps(record))
        if record["status"] == "runner_failure":
            self.assertFalse(record["process_termination_verified"])
            self.assertIn("process_termination_unverified", record["error_categories"])

    def test_timeout_kills_child_even_after_parent_exits_and_calls_owned_cleanup(self):
        cleanup_calls: list[bool] = []
        with tempfile.TemporaryDirectory(prefix="wp5-build-timeout-test-") as tmp:
            marker = Path(tmp) / "child-survived"
            pidfile = Path(tmp) / "child.pid"
            child = (
                "import signal,time,pathlib,os; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())); "
                f"time.sleep(2); pathlib.Path({str(marker)!r}).write_text('survived')"
            )
            parent = (
                "import subprocess,sys; subprocess.Popen([sys.executable,'-c',"
                f"{child!r}]); import time; time.sleep(0.05); print('parent-exited',flush=True)"
            )

            def cleanup_test_child() -> str:
                if pidfile.exists():
                    try:
                        os.kill(int(pidfile.read_text(encoding="ascii")), 9)
                    except ProcessLookupError:
                        pass
                cleanup_calls.append(True)
                return "removed"

            started = time.monotonic()
            record = CAPTURE.run_bounded_command(
                run_python(parent),
                phase="runtime_module_compile",
                known_projects=set(),
                timeout_seconds=0.25,
                cleanup_owned=cleanup_test_child,
                term_grace_seconds=0.1,
                kill_grace_seconds=0.5,
            )
            elapsed = time.monotonic() - started
            time.sleep(0.1)
            self.assertIn(record["status"], {"timeout", "runner_failure"})
            self.assertEqual(record["timeout_source"], "host")
            self.assertEqual(record["owned_container_cleanup"], "removed")
            self.assertEqual(cleanup_calls, [True])
            self.assertFalse(marker.exists())
            self.assertLess(elapsed, 3)
            if record["status"] == "runner_failure":
                self.assertFalse(record["process_termination_verified"])
                self.assertIn("process_termination_unverified", record["error_categories"])

    def test_container_timeout_exit_code_is_distinguished_from_host_timeout(self):
        record = CAPTURE.run_bounded_command(
            run_python("raise SystemExit(124)"),
            phase="runtime_module_compile",
            known_projects=set(),
            timeout_seconds=5,
        )
        self.assertEqual(record["status"], "timeout")
        self.assertEqual(record["timeout_source"], "container")
        self.assertTrue(record["timed_out"])
        self.assertIn("timeout", record["error_categories"])

    def test_process_group_permission_error_fails_closed_and_still_cleans_owned_container(self):
        cleanup_calls: list[bool] = []
        with mock.patch.object(CAPTURE.os, "killpg", side_effect=PermissionError):
            record = CAPTURE.run_bounded_command(
                run_python("import sys,time; print('bounded',flush=True); time.sleep(5)"),
                phase="runtime_module_compile",
                known_projects=set(),
                timeout_seconds=0.2,
                cleanup_owned=lambda: cleanup_calls.append(True) or "removed",
                term_grace_seconds=0.1,
                kill_grace_seconds=0.1,
            )
        self.assertEqual(record["status"], "runner_failure")
        self.assertFalse(record["process_termination_verified"])
        self.assertIn("process_termination_unverified", record["error_categories"])
        self.assertEqual(record["owned_container_cleanup"], "removed")
        self.assertEqual(cleanup_calls, [True])


class V4DiagnosticParserTests(unittest.TestCase):
    @staticmethod
    def inventory() -> CAPTURE.ProjectInventory:
        return CAPTURE.ProjectInventory(
            projects={"safe-runtime"},
            aliases={"safe-runtime": {"safe-runtime"}, "Keycloak Runtime: Demo": {"safe-runtime"}},
            modules=[CAPTURE.ModuleIdentity("quarkus/runtime", "safe-runtime")],
            tracked_paths={"quarkus/runtime/src/main/java/example/RuntimeSource.java"},
        )

    def test_ansi_split_across_reads_normalizes_plugin_start_and_maven3_failure_row(self):
        stream = CAPTURE.StreamDigest("stdout")
        observations = CAPTURE.Observations()
        inventory = self.inventory()
        first = b"\x1b[3"
        second = (
            b"2m[INFO]\x1b[0m --- compiler:3.13.0:compile (default-compile) @ safe-runtime ---\n"
            b"\x1b[36m[INFO]\x1b[0m Keycloak Runtime: Demo ........ FAILURE [ 01:23 min ]\n"
        )
        self.assertTrue(CAPTURE._feed_stream(stream, first, inventory, observations, CAPTURE.MAX_LINE_BYTES))
        self.assertTrue(CAPTURE._feed_stream(stream, second, inventory, observations, CAPTURE.MAX_LINE_BYTES))
        self.assertEqual(observations.plugin_started, {"compiler"})
        self.assertEqual(observations.reactor_failures, {"safe-runtime"})
        self.assertEqual(observations.projects, {"safe-runtime"})
        self.assertTrue(observations.parser_complete)

    def test_unknown_failed_goal_keeps_known_project_without_inventing_goal(self):
        line = (
            "[ERROR] Failed to execute goal vendor:unlisted-plugin:1.2:compile "
            "on project safe-runtime: opaque detail\n"
        )
        record = CAPTURE.run_bounded_command(
            run_python(f"import sys; sys.stdout.write({line!r}); sys.exit(1)"),
            phase="runtime_module_compile",
            known_projects=self.inventory(),
            timeout_seconds=5,
        )
        self.assertEqual(record["failed_goal_project_ids"], ["safe-runtime"])
        self.assertEqual(record["project_ids"], ["safe-runtime"])
        self.assertEqual(record["goal_categories"], [])
        self.assertIn("maven_goal_failure", record["error_categories"])
        self.assertNotIn("unlisted-plugin", json.dumps(record))
        self.assertNotIn("opaque detail", json.dumps(record))

    def test_compiler_diagnostic_emits_only_tracked_reactor_path_line_and_enum(self):
        line = (
            "[ERROR] /workspace/source/quarkus/runtime/src/main/java/example/RuntimeSource.java:"
            "[42,7] cannot find symbol\n"
        )
        record = CAPTURE.run_bounded_command(
            run_python(f"import sys; sys.stderr.write({line!r}); sys.exit(1)"),
            phase="runtime_module_compile",
            known_projects=self.inventory(),
            timeout_seconds=5,
        )
        self.assertEqual(record["compiler_diagnostic_categories"], ["cannot_find_symbol"])
        self.assertEqual(record["compiler_diagnostic_count"], 1)
        self.assertEqual(record["unknown_diagnostic_count"], 0)
        self.assertEqual(record["project_ids"], ["safe-runtime"])
        self.assertEqual(record["diagnostic_locations"], [{
            "path": "quarkus/runtime/src/main/java/example/RuntimeSource.java",
            "line": 42,
            "category": "cannot_find_symbol",
        }])
        self.assertTrue(record["failure_location_identified"])

    def test_generated_or_out_of_src_diagnostic_path_is_omitted_but_failure_project_is_kept(self):
        secret_path = "/workspace/source/quarkus/runtime/target/generated-sources/RuntimeSource.java"
        lines = (
            f"[ERROR] {secret_path}:[8,2] incompatible types\n"
            "[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.14.0:compile "
            "on project safe-runtime: Compilation failure\n"
        )
        record = CAPTURE.run_bounded_command(
            run_python(f"import sys; sys.stdout.write({lines!r}); sys.exit(1)"),
            phase="runtime_module_compile",
            known_projects=self.inventory(),
            timeout_seconds=5,
        )
        serialized = json.dumps(record, sort_keys=True)
        self.assertEqual(record["project_ids"], ["safe-runtime"])
        self.assertEqual(record["goal_categories"], ["compiler"])
        self.assertEqual(record["compiler_diagnostic_categories"], ["incompatible_types"])
        self.assertEqual(record["diagnostic_locations"], [])
        self.assertFalse(record["failure_location_identified"])
        self.assertNotIn("generated-sources", serialized)

    def test_unknown_compiler_diagnostic_is_count_only_and_generic_error_is_not_compiler_failure(self):
        unknown = (
            "[ERROR] /workspace/source/quarkus/runtime/src/main/java/example/RuntimeSource.java:"
            "[9,2] undocumented compiler condition SECRET_SYMBOL\n"
        )
        record = CAPTURE.run_bounded_command(
            run_python(f"import sys; sys.stdout.write({unknown!r}); sys.exit(1)"),
            phase="runtime_module_compile",
            known_projects=self.inventory(),
            timeout_seconds=5,
        )
        self.assertEqual(record["compiler_diagnostic_count"], 1)
        self.assertEqual(record["unknown_diagnostic_count"], 1)
        self.assertEqual(record["compiler_diagnostic_categories"], [])
        self.assertEqual(record["diagnostic_locations"], [])
        self.assertNotIn("SECRET_SYMBOL", json.dumps(record))

        generic = CAPTURE.run_bounded_command(
            run_python("import sys; sys.stderr.write('general error: not a javac diagnostic\\n'); sys.exit(1)"),
            phase="runtime_module_compile",
            known_projects=self.inventory(),
            timeout_seconds=5,
        )
        self.assertNotIn("compiler_failure", generic["error_categories"])
        self.assertEqual(generic["compiler_diagnostic_count"], 0)

    def test_unterminated_ansi_marks_parser_incomplete_without_changing_stream_completeness(self):
        record = CAPTURE.run_bounded_command(
            run_python("import sys; sys.stdout.write('[INFO]\\x1b[31')"),
            phase="runtime_module_compile",
            known_projects=self.inventory(),
            timeout_seconds=5,
        )
        self.assertEqual(record["status"], "success")
        self.assertTrue(record["stdout"]["capture_complete"])
        self.assertFalse(record["parser_complete"])
        self.assertEqual(record["parser_incomplete_line_count"], 1)
        self.assertEqual(record["invalid_control_sequence_count"], 1)
        with tempfile.TemporaryDirectory(prefix="wp5-v4-compile-gate-") as tmp:
            receipt = Path(tmp) / "compile.json"
            payload = {
                **record,
                "source_commit": CAPTURE.PINNED_COMMIT,
                "observer_sha256": CAPTURE.OBSERVER_SHA256,
                "handler_sha256": CAPTURE.HANDLER_AFTER_SHA256,
            }
            old_path = CAPTURE._phase_receipt_path
            try:
                CAPTURE._phase_receipt_path = lambda phase: receipt
                receipt.write_text(json.dumps(payload))
                receipt.chmod(0o600)
                with self.assertRaises(CAPTURE.CaptureError):
                    CAPTURE._require_successful_compile_receipt()
            finally:
                CAPTURE._phase_receipt_path = old_path

    def test_ansi_normalizer_strips_complete_osc_and_rejects_incomplete_control(self):
        self.assertEqual(
            CAPTURE._normalize_terminal_controls(b"[INFO]\x1b]0;private title\x07 ok"),
            b"[INFO] ok",
        )
        self.assertIsNone(CAPTURE._normalize_terminal_controls(b"[ERROR]\x1b]0;unterminated"))


class SourceBindingAndPhaseTests(unittest.TestCase):
    def test_project_allowlist_follows_root_reactor_modules_and_ignores_unreferenced_fixture_pom(self):
        with tempfile.TemporaryDirectory(prefix="wp5-pom-whitelist-") as tmp:
            source = Path(tmp) / "source"
            source.mkdir()
            git = lambda *args: subprocess.run(["git", "-C", str(source), *args], check=True, capture_output=True)
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            pom = (
                "<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>demo-root</artifactId>"
                "<name>Root: Demo Reactor</name>"
                "<version>1</version><modules><module>runtime</module></modules>"
                "<profiles><profile><id>fixture</id><modules><module>profile-module</module></modules></profile></profiles></project>"
            )
            (source / "pom.xml").write_text(pom)
            for name, artifact, display in (
                ("runtime", "safe-runtime", "Keycloak Runtime: Demo"),
                ("profile-module", "safe-profile", "Fixture Profile Module"),
            ):
                module = source / name
                module.mkdir()
                (module / "pom.xml").write_text(f"<project><artifactId>{artifact}</artifactId><name>{display}</name></project>")
            runtime_source = source / "runtime/src/main/java/example/RuntimeSource.java"
            runtime_source.parent.mkdir(parents=True)
            runtime_source.write_text("class RuntimeSource {}\n")
            fixture = source / "test-fixtures" / "malformed"
            fixture.mkdir(parents=True)
            (fixture / "pom.xml").write_text("not xml")
            handler = source / CAPTURE.HANDLER_RELATIVE
            handler.parent.mkdir(parents=True)
            handler.write_text("source handler")
            git("add", "pom.xml", "runtime/pom.xml", "runtime/src/main/java/example/RuntimeSource.java", "profile-module/pom.xml", "test-fixtures/malformed/pom.xml", str(CAPTURE.HANDLER_RELATIVE))
            env = {**os.environ, "GIT_AUTHOR_NAME": "WP5 test", "GIT_AUTHOR_EMAIL": "wp5@example.invalid", "GIT_COMMITTER_NAME": "WP5 test", "GIT_COMMITTER_EMAIL": "wp5@example.invalid"}
            subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True, env=env)
            (source / CAPTURE.HANDLER_RELATIVE).write_text("patched handler")
            observer = source / CAPTURE.OBSERVER_RELATIVE
            observer.write_text("observer")

            old = (CAPTURE.V4_SOURCE, CAPTURE.PINNED_COMMIT, CAPTURE.HANDLER_AFTER_SHA256, CAPTURE.OBSERVER_SHA256)
            try:
                CAPTURE.V4_SOURCE = source.resolve()
                CAPTURE.PINNED_COMMIT = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
                CAPTURE.HANDLER_AFTER_SHA256 = hashlib.sha256(b"patched handler").hexdigest()
                CAPTURE.OBSERVER_SHA256 = hashlib.sha256(b"observer").hexdigest()
                projects = CAPTURE._project_ids_from_poms(source)
            finally:
                CAPTURE.V4_SOURCE, CAPTURE.PINNED_COMMIT, CAPTURE.HANDLER_AFTER_SHA256, CAPTURE.OBSERVER_SHA256 = old
            self.assertEqual(projects.projects, {"demo-root", "safe-runtime", "safe-profile"})
            self.assertEqual(projects.canonical_project("Keycloak Runtime: Demo"), "safe-runtime")
            self.assertEqual(
                projects.project_for_source_path("runtime/src/main/java/example/RuntimeSource.java"),
                "safe-runtime",
            )
            self.assertIsNone(projects.project_for_source_path("runtime/target/generated-sources/RuntimeSource.java"))
            self.assertIsNone(projects.canonical_project("unlisted-project-name"))

    def test_server_build_command_is_exact_and_receipt_gated(self):
        command, name = CAPTURE._phase_command("server_distribution_build")
        self.assertEqual(name, CAPTURE.V4_CONTAINER)
        self.assertIn("--memory=8g", command)
        self.assertIn("MAVEN_OPTS=-Xmx4g", command)
        shell = command[-1]
        self.assertIn("45m ./mvnw -B -Dstyle.color=never -ntp -pl quarkus/deployment,quarkus/dist -am -DskipTests clean install", shell)
        self.assertIn("install -m 0600 quarkus/dist/target/keycloak-26.7.4.zip", shell)
        self.assertNotIn("/dev/null", shell)
        with tempfile.TemporaryDirectory(prefix="wp5-compile-receipt-") as tmp:
            receipt = Path(tmp) / "compile.json"
            good = {
                "schema_version": 2, "parser_schema_version": 1,
                "phase": "runtime_module_compile", "status": "success", "source_commit": CAPTURE.PINNED_COMMIT,
                "exit_code": 0, "timed_out": False, "output_limit_reason": "none",
                "parser_complete": True, "parser_incomplete_line_count": 0,
                "invalid_control_sequence_count": 0, "diagnostic_counts_saturated": False,
                "compiler_diagnostic_count": 0, "unknown_diagnostic_count": 0,
                "failure_location_identified": False, "diagnostic_locations": [],
                "diagnostic_locations_truncated": False, "failed_goal_project_ids": [],
                "reactor_failure_project_ids": [], "error_categories": [], "goal_categories": [],
                "stdout": {"capture_complete": True}, "stderr": {"capture_complete": True},
                "observer_sha256": CAPTURE.OBSERVER_SHA256, "handler_sha256": CAPTURE.HANDLER_AFTER_SHA256,
            }
            old_path = CAPTURE._phase_receipt_path
            try:
                CAPTURE._phase_receipt_path = lambda phase: receipt
                receipt.write_text(json.dumps(good))
                receipt.chmod(0o600)
                CAPTURE._require_successful_compile_receipt()
                good["stdout"]["capture_complete"] = False
                receipt.write_text(json.dumps(good))
                receipt.chmod(0o600)
                with self.assertRaises(CAPTURE.CaptureError):
                    CAPTURE._require_successful_compile_receipt()
            finally:
                CAPTURE._phase_receipt_path = old_path

    def test_compile_receipt_gate_rejects_fifo_before_opening_it(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("named pipes are unavailable")
        with tempfile.TemporaryDirectory(prefix="wp5-compile-fifo-") as tmp:
            receipt = Path(tmp) / "compile.json"
            os.mkfifo(receipt, 0o600)
            old_path = CAPTURE._phase_receipt_path
            try:
                CAPTURE._phase_receipt_path = lambda phase: receipt
                with self.assertRaises(CAPTURE.CaptureError):
                    CAPTURE._require_successful_compile_receipt()
            finally:
                CAPTURE._phase_receipt_path = old_path

    def test_phase_attempt_claim_is_exclusive_and_mode_0600(self):
        with tempfile.TemporaryDirectory(prefix="wp5-phase-claim-") as tmp:
            marker = Path(tmp) / "attempt.json"
            old_path = CAPTURE._phase_attempt_path
            try:
                CAPTURE._phase_attempt_path = lambda phase: marker
                CAPTURE._claim_phase_attempt("runtime_module_compile")
                self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
                with self.assertRaises(CAPTURE.CaptureError):
                    CAPTURE._claim_phase_attempt("runtime_module_compile")
            finally:
                CAPTURE._phase_attempt_path = old_path


class OwnedContainerCleanupTests(unittest.TestCase):
    def test_cleanup_uses_exact_docker_name_filter_and_refuses_label_mismatch(self):
        container_name = CAPTURE.V4_CONTAINER
        listing = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=f"{container_name} different-owner {CAPTURE.PHASE_LABEL_VALUE}\n".encode(),
            stderr=b"",
        )
        with mock.patch.object(CAPTURE.subprocess, "run", return_value=listing) as run:
            result = CAPTURE._cleanup_exact_container(container_name)

        self.assertEqual(result, "ownership_mismatch")
        self.assertEqual(run.call_count, 1)
        argv = run.call_args.args[0]
        filter_index = argv.index("--filter")
        self.assertEqual(argv[filter_index + 1], f"name=^/{container_name}$")
        self.assertNotIn("rm", argv)


class OwnedContainerCleanupTests(unittest.TestCase):
    def test_cleanup_uses_exact_docker_name_filter_and_refuses_label_mismatch(self):
        container_name = CAPTURE.V4_CONTAINER
        listing = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=f"{container_name} different-owner {CAPTURE.PHASE_LABEL_VALUE}\n".encode(),
            stderr=b"",
        )
        with mock.patch.object(CAPTURE.subprocess, "run", return_value=listing) as run:
            result = CAPTURE._cleanup_exact_container(container_name)

        self.assertEqual(result, "ownership_mismatch")
        self.assertEqual(run.call_count, 1)
        argv = run.call_args.args[0]
        filter_index = argv.index("--filter")
        self.assertEqual(argv[filter_index + 1], f"name=^/{container_name}$")
        self.assertNotIn("rm", argv)


if __name__ == "__main__":
    unittest.main()
