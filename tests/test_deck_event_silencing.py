#!/usr/bin/env python3
"""Real CLI/subprocess boundary with a private, offline fake decK executable."""

import copy
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


class DeckEventSilencingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="deck-events-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        selector.fixture_tree(self.root)
        self.report = selector.additive_report()
        self.report["changes"]["creating"][0]["body"]["new"]["dummy_private"] = "private-body-sentinel"
        selector.write_wp5_receipt(self.root, self.report)
        self.report_path = self.root / "report.json"
        self.report_path.write_text(json.dumps(self.report))
        self.bin = self.root / "bin"
        self.bin.mkdir(mode=0o700)
        self.calls = self.root / "calls.jsonl"
        executable = self.bin / "deck"
        executable.write_text("#!" + sys.executable + "\n" + '''import json,os,sys
from pathlib import Path
with Path(os.environ["FAKE_DECK_CALLS"]).open("a") as out:
    out.write(json.dumps(sys.argv[1:])+"\\n")
if sys.argv[2] == "diff":
    if "--silence-events" not in sys.argv or os.environ.get("FAKE_DECK_BANNER") == "YES":
        print("creating service dummy-event")
    print(Path(os.environ["FAKE_DECK_REPORT"]).read_text())
elif sys.argv[2] == "sync":
    print("private-body-sentinel")
else:
    sys.exit(9)
''')
        executable.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, mode, *, banner=False, source=None):
        runner = ROOT / "scripts/run-deck.py"
        if source is not None:
            runner = self.root / "mutant-runner.py"
            runner.write_text(source)
        # Original main, argument parser, local gates, strict report parser and
        # run_deck_subprocess execute. Only remote target/schema APIs are mocked.
        driver = '''import importlib.util,sys
sys.path.insert(0,sys.argv[1])
spec=importlib.util.spec_from_file_location("event_runner",sys.argv[2])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.verify_remote_target=lambda *args,**kwargs: None
m.check_schemas=lambda *args,**kwargs: None
sys.argv=[sys.argv[2],sys.argv[4],"--root",sys.argv[3],"--gateway","third-party","--stage","runtime"]
try: sys.exit(m.main())
except ValueError as error: print(str(error));sys.exit(7)
'''
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
               "TP_BACKEND_RUNTIME_V2_APPROVED": "YES", "FAKE_DECK_REPORT": str(self.report_path),
               "FAKE_DECK_CALLS": str(self.calls), "FAKE_DECK_BANNER": "YES" if banner else "NO"}
        return subprocess.run([sys.executable, "-B", "-c", driver, str(ROOT / "scripts"), str(runner), str(self.root), mode],
                              env=env, capture_output=True, text=True, timeout=15)

    def invoked(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_requested_diff_and_pre_sync_diff_silence_events(self):
        for mode, expected in (("diff", ["diff"]), ("sync", ["diff", "sync"])):
            with self.subTest(mode=mode):
                self.calls.unlink(missing_ok=True)
                result = self.run_cli(mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                commands = self.invoked()
                self.assertEqual([command[1] for command in commands], expected)
                self.assertIn("--silence-events", commands[0])
                self.assertIn("--json-output", commands[0])
                self.assertNotIn("private-body-sentinel", result.stdout + result.stderr)
                self.assertNotIn("dummy-event", result.stdout + result.stderr)
                if mode == "diff":
                    output = next(json.loads(line) for line in result.stdout.splitlines() if line.startswith("{"))
                    self.assertEqual(output["summary"], {"creating": 4, "updating": 6, "deleting": 0, "total": 10})
                    self.assertIn("TP_BACKEND_RUNTIME_V2_DIFF_SHA256=", result.stdout)
                else:
                    self.assertNotIn("--silence-events", commands[1])

    def test_banner_prefixed_and_error_json_still_fail_closed(self):
        for mode in ("diff", "sync"):
            for invalid in ("banner", "error"):
                with self.subTest(mode=mode, invalid=invalid):
                    self.calls.unlink(missing_ok=True)
                    report = copy.deepcopy(self.report)
                    if invalid == "error":
                        report["errors"] = ["private-error-sentinel"]
                    self.report_path.write_text(json.dumps(report))
                    result = self.run_cli(mode, banner=invalid == "banner")
                    self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
                    self.assertIn("did not return valid JSON" if invalid == "banner" else "contains errors, warnings", result.stdout)
                    self.assertEqual([command[1] for command in self.invoked()], ["diff"])
                    for raw in ("private-error-sentinel", "private-body-sentinel", "dummy-event"):
                        self.assertNotIn(raw, result.stdout + result.stderr)

    def test_each_silencing_flag_semantic_mutation_is_killed(self):
        original = (ROOT / "scripts/run-deck.py").read_text()
        mutations = (
            ("diff", '            command.append("--silence-events")\n', ""),
            ("sync", ', "--silence-events"]', ']'),
        )
        for mode, before, after in mutations:
            with self.subTest(mode=mode):
                self.assertEqual(original.count(before), 1)
                self.calls.unlink(missing_ok=True)
                result = self.run_cli(mode, source=original.replace(before, after))
                # A missing flag produces a real process event prefix: the
                # original success property fails because strict JSON rejects it.
                self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
                self.assertIn("did not return valid JSON", result.stdout)
                self.assertEqual([command[1] for command in self.invoked()], ["diff"])
                print("event-silencing semantic mutation killed:", mode)


if __name__ == "__main__":
    unittest.main(verbosity=2)
