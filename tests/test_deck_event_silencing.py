#!/usr/bin/env python3
"""Strict TP JSON and recovery approval through real CLI/subprocess boundaries."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests import test_wp5_deck_selector as selector

# Independently frozen from official reconciler v1.29.2 utils.go36-49,238-262
# and builder.go1388-1406, never imported from the production constant.
ADVISORY = (
    "1 unsupported routes' paths format with Kong version 3.0\n"
    'or above were detected. Some of these routes are (not an exhaustive list):\n'
    '\n'
    'aaced8a8-6936-520b-96ea-026a7b01b4b6\n'
    ' paths:~^/$\n'
    '       ~^/index\\.html$\n'
    '       ~^/evidence\\.js$\n'
    '\n'
    'Please upgrade your configuration to account for 3.0\n'
    'breaking changes using the following command:\n'
    '\n'
    'deck convert --from kong-gateway-2.x --to kong-gateway-3.x\n'
    '\n'
    'This command performs the following changes:\n'
    '  - upgrade the `_format_version` value to `3.0`\n'
    "  - add the `~` prefix to all routes' paths containing a regex-pattern\n"
    '\n'
    'These changes may not be correct or exhaustive enough.\n'
    'It is strongly recommended to perform a manual audit\n'
    'of the updated configuration file before applying\n'
    'the configuration in production. Incorrect changes will result in\n'
    'unintended traffic routing by Kong Gateway.\n'
    '\n'
    'For more information about this and related changes,\n'
    'please visit: https://docs.konghq.com/deck/latest/3.0-upgrade\n'
    '\n'
)


class DeckPureJSONTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="deck-advisory-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        selector.fixture_tree(self.root)
        self.report = selector.additive_report("migration-recovery")
        self.report["changes"]["creating"][0]["body"]["new"]["dummy_private"] = "private-body-sentinel"
        selector.write_wp5_receipt(self.root, self.report, "migration-recovery")
        self.report_path = self.root / "report.json"
        self.prefix_path = self.root / "prefix.txt"
        self.bin = self.root / "bin"
        self.bin.mkdir(mode=0o700)
        self.calls = self.root / "calls.jsonl"
        executable = self.bin / "deck"
        executable.write_text("#!" + sys.executable + "\n" + """import json,os,sys
from pathlib import Path
with Path(os.environ["FAKE_DECK_CALLS"]).open("a") as out:
    out.write(json.dumps(sys.argv[1:])+"\\n")
if sys.argv[2] == "validate":
    import time
    if os.environ.get("FAKE_VALIDATE_TIMEOUT") == "YES": time.sleep(1)
    if os.environ.get("FAKE_VALIDATE_STDERR") == "YES": print("private-error-sentinel",file=sys.stderr)
    print("private-body-sentinel")
    sys.exit(int(os.environ.get("FAKE_VALIDATE_EXIT","0")))
elif sys.argv[2] == "diff":
    # Actual 1.53.1 silence-events suppresses the JSON report too.
    if "--silence-events" not in sys.argv:
        sys.stdout.write(Path(os.environ["FAKE_DECK_PREFIX"]).read_text())
        sys.stdout.write(Path(os.environ["FAKE_DECK_REPORT"]).read_text())
    if os.environ.get("FAKE_DECK_STDERR") == "YES":
        print("private-error-sentinel",file=sys.stderr)
    sys.exit(int(os.environ.get("FAKE_DECK_EXIT","0")))
elif sys.argv[2] == "sync":
    print("private-body-sentinel")
else:
    sys.exit(9)
""")
        executable.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, mode, *, prefix="", raw=None, exit_code=0, stderr=False, source=None, validation_exit=0, validation_stderr=False, validation_timeout=False):
        self.calls.unlink(missing_ok=True)
        self.prefix_path.write_text(prefix)
        self.report_path.write_text(json.dumps(self.report) if raw is None else raw)
        runner = ROOT / "scripts/run-deck.py"
        if source is not None:
            runner = self.root / "mutant-runner.py"
            runner.write_text(source)
        # Original main/argv, source/receipt gates, adapter/strict parser and
        # run_deck_subprocess execute; only target/schema network APIs are mocked.
        driver = """import importlib.util,sys,os
sys.path.insert(0,sys.argv[1])
spec=importlib.util.spec_from_file_location("advisory_runner",sys.argv[2])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.verify_remote_target=lambda *args,**kwargs: None
m.check_schemas=lambda *args,**kwargs: None
if os.environ.get("FAKE_VALIDATE_TIMEOUT")=="YES": m.DECK_SUBPROCESS_TIMEOUT_SECONDS=0.2
sys.argv=[sys.argv[2],sys.argv[4],"--root",sys.argv[3],"--gateway","third-party","--stage","runtime"]
try: sys.exit(m.main())
except ValueError as error: print(str(error));sys.exit(7)
"""
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
               "TP_BACKEND_RUNTIME_V2_APPROVED": "YES", "FAKE_DECK_REPORT": str(self.report_path),
               "FAKE_DECK_PREFIX": str(self.prefix_path), "FAKE_DECK_CALLS": str(self.calls),
               "FAKE_DECK_STDERR": "YES" if stderr else "NO", "FAKE_DECK_EXIT": str(exit_code),
               "FAKE_VALIDATE_EXIT": str(validation_exit), "FAKE_VALIDATE_STDERR": "YES" if validation_stderr else "NO",
               "FAKE_VALIDATE_TIMEOUT": "YES" if validation_timeout else "NO"}
        return subprocess.run([sys.executable, "-B", "-c", driver, str(ROOT / "scripts"), str(runner), str(self.root), mode],
                              env=env, capture_output=True, text=True, timeout=15)

    def invoked(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def assert_private_output_absent(self, result):
        for raw in ("private-error-sentinel", "private-body-sentinel", "aaced8a8-6936-520b-96ea-026a7b01b4b6\n paths:"):
            self.assertNotIn(raw, result.stdout + result.stderr)

    def assert_success(self, mode, **kwargs):
        result = self.run_cli(mode, **kwargs)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = self.invoked()
        self.assertEqual([command[1] for command in commands], ["diff"] if mode == "diff" else ["validate", "diff", "sync"])
        diff_command = commands[0] if mode == "diff" else commands[1]
        self.assertNotIn("--silence-events", diff_command)
        self.assertIn("--json-output", diff_command)
        if mode == "sync":
            self.assertEqual(commands[0][commands[0].index("--online-entities-list") + 1], "Routes")
            self.assertEqual(commands[0][commands[0].index("--parallelism") + 1], "1")
        self.assert_private_output_absent(result)
        if mode == "diff":
            output = next(json.loads(line) for line in result.stdout.splitlines() if line.startswith("{"))
            self.assertEqual(output["summary"], {"creating": 2, "updating": 4, "deleting": 0, "total": 6})
            self.assertIn("TP_BACKEND_RUNTIME_V2_DIFF_SHA256=", result.stdout)

    def assert_rejected(self, mode, expected_calls=None, **kwargs):
        result = self.run_cli(mode, **kwargs)
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertEqual([command[1] for command in self.invoked()],
                         expected_calls or (["diff"] if mode == "diff" else ["validate", "diff"]))
        self.assert_private_output_absent(result)

    def test_original_pure_json_parser_rejects_the_historical_advisory(self):
        self.assertEqual(len(ADVISORY.encode()), 941)
        self.assertEqual(hashlib.sha256(ADVISORY.encode()).hexdigest(), "1c53dfed2bbacb076dfdf079287707b63aeb4524cb712fc9e5c2af611724a571")
        self.assertFalse(hasattr(selector.run_deck, "parse_backend_cli_runtime_diff"))
        self.assertFalse(hasattr(selector.run_deck, "BACKEND_DECK_REGEX_ADVISORY"))
        selector.run_deck.parse_sanitized_runtime_diff(json.dumps(self.report))
        with self.assertRaisesRegex(ValueError, "did not return valid JSON"):
            selector.run_deck.parse_sanitized_runtime_diff(ADVISORY + json.dumps(self.report))

    def test_requested_and_pre_sync_accept_only_pure_json(self):
        for mode in ("diff", "sync"):
            with self.subTest(mode=mode):
                self.assert_success(mode)

    def test_old_migration_receipt_cannot_authorize_recovery(self):
        selector.write_wp5_receipt(self.root, selector.additive_report())
        self.assert_rejected("sync")

    def test_invalid_framing_report_and_process_results_fail_closed(self):
        pure = json.dumps(self.report)
        warning = copy.deepcopy(self.report)
        warning["warnings"] = ["private-error-sentinel"]
        error = copy.deepcopy(self.report)
        error["errors"] = ["private-error-sentinel"]
        invalid = {
            "empty": {"prefix": "", "raw": ""},
            "advisory_only": {"prefix": ADVISORY, "raw": ""},
            "historical_advisory": {"prefix": ADVISORY},
            "count": {"prefix": ADVISORY.replace("1 unsupported", "2 unsupported")},
            "route_id": {"prefix": ADVISORY.replace("aaced8a8", "baced8a8")},
            "last_path": {"prefix": ADVISORY.replace("evidence\\.js", "foreign\\.js")},
            "last_text": {"prefix": ADVISORY.replace("3.0-upgrade", "3.1-upgrade")},
            "missing_newline": {"prefix": ADVISORY[:-1]},
            "repeat": {"prefix": ADVISORY + ADVISORY},
            "other_prefix": {"prefix": "private-error-sentinel\n"},
            "leading_whitespace": {"prefix": "\n" + ADVISORY},
            "ansi": {"prefix": "\x1b[33m" + ADVISORY},
            "trailing_diagnostic": {"raw": pure + "\nprivate-error-sentinel"},
            "two_reports": {"raw": pure + pure},
            "duplicate_field": {"raw": pure[:-1] + ',"errors":[]}'},
            "nonfinite": {"raw": pure.replace('"dummy_private": "private-body-sentinel"', '"dummy_private": NaN')},
            "warnings": {"raw": json.dumps(warning)},
            "errors": {"raw": json.dumps(error)},
            "nonzero": {"exit_code": 1},
            "stderr": {"stderr": True},
        }
        for mode in ("diff", "sync"):
            for name, kwargs in invalid.items():
                with self.subTest(mode=mode, invalid=name):
                    self.assert_rejected(mode, **kwargs)

    def test_route_validation_failures_stop_before_diff_or_sync(self):
        for kwargs in ({"validation_exit": 1}, {"validation_stderr": True}, {"validation_timeout": True}):
            with self.subTest(kwargs=kwargs):
                result = self.run_cli("sync", **kwargs)
                self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
                self.assertIn("route validation failed; sync was not attempted", result.stdout)
                self.assertNotIn("outcome is unknown", result.stdout)
                self.assertEqual([command[1] for command in self.invoked()], ["validate"])
                self.assert_private_output_absent(result)

    def test_semantic_mutations_are_killed_for_behavioral_reasons(self):
        original = (ROOT / "scripts/run-deck.py").read_text()
        mutations = (
            ("arbitrary_prefix", "    try:\n        report = json.loads(",
             '    raw_output = raw_output[raw_output.index("{"):]\n    try:\n        report = json.loads(', "reject_prefix"),
            ("requested_silence", '            command.append("--no-mask-deck-env-vars-value")',
             '            command.append("--no-mask-deck-env-vars-value")\n            command.append("--silence-events")', "diff"),
            ("pre_sync_silence", 'diff_command.extend(["--json-output", "--no-color", "--no-mask-deck-env-vars-value"])',
             'diff_command.extend(["--json-output", "--no-color", "--no-mask-deck-env-vars-value", "--silence-events"])', "sync"),
            ("validation_nonzero", "if validation_result.returncode != 0 or validation_result.stderr.strip():",
             "if validation_result.stderr.strip():", "reject_validation"),
            ("error_leniency", 'or report["warnings"] != [] or report["errors"] != []:',
             'or report["warnings"] != []:', "reject_errors"),
        )
        for name, before, after, property_name in mutations:
            with self.subTest(mutation=name):
                self.assertEqual(original.count(before), 1)
                changed = original.replace(before, after)
                if property_name == "reject_prefix":
                    call = lambda: self.assert_rejected("sync", prefix="private-error-sentinel\n", source=changed)
                elif property_name == "reject_validation":
                    call = lambda: self.assert_rejected("sync", expected_calls=["validate"], validation_exit=1, source=changed)
                elif property_name == "reject_errors":
                    report = copy.deepcopy(self.report)
                    report["errors"] = ["private-error-sentinel"]
                    call = lambda: self.assert_rejected("diff", raw=json.dumps(report), source=changed)
                else:
                    call = lambda: self.assert_success(property_name, source=changed)
                if property_name == "reject_prefix":
                    observed = self.run_cli("sync", prefix="private-error-sentinel\\n", source=changed)
                elif property_name == "reject_validation":
                    observed = self.run_cli("sync", validation_exit=1, source=changed)
                elif property_name == "reject_errors":
                    observed = self.run_cli("diff", raw=json.dumps(report), source=changed)
                else:
                    observed = self.run_cli(property_name, source=changed)
                self.assertEqual(observed.returncode, 0 if property_name.startswith("reject") else 7,
                                 observed.stdout + observed.stderr)
                if not property_name.startswith("reject"):
                    self.assertIn("did not return valid JSON", observed.stdout)
                self.assertNotIn("Traceback", observed.stderr)
                result = unittest.TestResult()
                unittest.TestSuite([unittest.FunctionTestCase(call)]).run(result)
                self.assertEqual(result.errors, [], "mutation must not fail from setup/import")
                self.assertTrue(result.failures, "semantic mutation survived")
                print("CLI pure JSON semantic mutation killed:", name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
