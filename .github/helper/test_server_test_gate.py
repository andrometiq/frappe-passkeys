# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Process-boundary tests for the fail-closed server-test wrapper."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / ".github" / "helper" / "run_server_tests.sh"


class ServerTestGateTest(unittest.TestCase):
	def setUp(self):
		self.directory = tempfile.TemporaryDirectory()
		self.addCleanup(self.directory.cleanup)
		self.bin_directory = Path(self.directory.name)
		self.args_file = self.bin_directory / "args.json"
		bench = self.bin_directory / "bench"
		bench.write_text(
			"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args_file = Path(os.environ["FAKE_BENCH_ARGS"])
if sys.argv[3] == "execute":
    phase = "AFTER" if args_file.exists() else "BEFORE"
    sys.stdout.write(os.environ.get("FAKE_SNAPSHOT_" + phase, ""))
    raise SystemExit(int(os.environ.get("FAKE_SNAPSHOT_STATUS_" + phase, "0")))
args_file.write_text(json.dumps(sys.argv[1:]), encoding="utf-8")
sys.stdout.write(os.environ.get("FAKE_BENCH_OUTPUT", ""))
raise SystemExit(int(os.environ.get("FAKE_BENCH_STATUS", "0")))
""",
			encoding="utf-8",
		)
		bench.chmod(0o755)

	def run_gate(
		self,
		output: str,
		status: int = 0,
		*,
		before="",
		after="",
		snapshot_status=0,
		baseline_status=0,
		options=(),
	):
		environment = os.environ.copy()
		environment.update(
			{
				"PATH": str(self.bin_directory) + os.pathsep + environment["PATH"],
				"FAKE_BENCH_ARGS": str(self.args_file),
				"FAKE_BENCH_OUTPUT": output,
				"FAKE_BENCH_STATUS": str(status),
				"FAKE_SNAPSHOT_BEFORE": before,
				"FAKE_SNAPSHOT_AFTER": after,
				"FAKE_SNAPSHOT_STATUS_AFTER": str(snapshot_status),
				"FAKE_SNAPSHOT_STATUS_BEFORE": str(baseline_status),
			}
		)
		return subprocess.run(
			["bash", str(GATE), "test_site", *options],
			cwd=ROOT,
			env=environment,
			capture_output=True,
			text=True,
			check=False,
		)

	def assert_rejected(self, output: str, status: int = 0):
		result = self.run_gate(output, status)
		self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

	def test_passing_nonempty_run_is_accepted_and_forwarded_exactly(self):
		output = (
			"expected nested-runner log\nFAILED (failures=1)\n"
			"RuntimeError: expected\nRan 3 tests in 0.100s\n\nOK\n"
		)
		result = self.run_gate(output)
		self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
		self.assertEqual(
			json.loads(self.args_file.read_text()), ["--site", "test_site", "run-tests", "--app", "passkeys"]
		)
		self.assertEqual(result.stdout, output + "server tests: no committed-state leaks\n")

	def test_module_options_are_forwarded(self):
		options = ["--module", "passkeys.tests.test_install"]
		result = self.run_gate("Ran 1 test in 0.010s\n\nOK\n", options=options)
		self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
		self.assertEqual(json.loads(self.args_file.read_text())[-2:], options)

	def test_unchanged_nonempty_baseline_is_accepted(self):
		baseline = '["Passkey Settings", "login_with_passkey", "1"]\n'
		result = self.run_gate("Ran 1 test in 0.010s\n\nOK\n", before=baseline, after=baseline)
		self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

	def test_added_and_removed_rows_are_named(self):
		result = self.run_gate(
			"Ran 1 test in 0.010s\n\nOK\n",
			before='["User", "passkey-test-before@example.com"]\n',
			after='["User", "passkey-test-after@example.com"]\n',
		)
		self.assertEqual(result.returncode, 1)
		self.assertIn('-["User", "passkey-test-before@example.com"]', result.stdout)
		self.assertIn('+["User", "passkey-test-after@example.com"]', result.stdout)
		self.assertIn("committed-state leak", result.stderr)

	def test_suite_failure_takes_precedence_but_still_reports_leak(self):
		result = self.run_gate("runner failed\n", status=7, after='["Role", "leaked"]\n')
		self.assertEqual(result.returncode, 7)
		self.assertLess(
			result.stderr.index("bench exited with status 7"), result.stderr.index("committed-state leak")
		)
		self.assertIn('+["Role", "leaked"]', result.stdout)

	def test_failed_summary_still_reports_leak(self):
		result = self.run_gate("Ran 1 test in 0.010s\n\nFAILED (errors=1)\n", after='["Role", "leaked"]\n')
		self.assertEqual(result.returncode, 1)
		self.assertLess(
			result.stderr.index("FAILED final summary"), result.stderr.index("committed-state leak")
		)

	def test_failed_post_suite_snapshot_is_rejected(self):
		result = self.run_gate("Ran 1 test in 0.010s\n\nOK\n", snapshot_status=5)
		self.assertEqual(result.returncode, 1)
		self.assertIn("could not snapshot committed state", result.stderr)

	def test_failed_baseline_stops_before_running_suite(self):
		result = self.run_gate("Ran 1 test in 0.010s\n\nOK\n", baseline_status=6)
		self.assertEqual(result.returncode, 6)
		self.assertFalse(self.args_file.exists())
		self.assertIn("before the suite", result.stderr)

	def test_suite_failure_precedes_post_snapshot_failure(self):
		result = self.run_gate("runner failed\n", status=7, snapshot_status=5)
		self.assertEqual(result.returncode, 7)
		self.assertIn("after the suite", result.stderr)

	def test_removal_only_is_rejected(self):
		result = self.run_gate("Ran 1 test in 0.010s\n\nOK\n", before='["User", "baseline"]\n')
		self.assertEqual(result.returncode, 1)
		self.assertIn("committed-state leak", result.stderr)

	def test_changed_contents_are_rejected(self):
		result = self.run_gate(
			"Ran 1 test in 0.010s\n\nOK\n",
			before='["WebAuthn Credential", "same-name", "old-key"]\n',
			after='["WebAuthn Credential", "same-name", "new-key"]\n',
		)
		self.assertEqual(result.returncode, 1)
		self.assertIn("old-key", result.stdout)
		self.assertIn("new-key", result.stdout)

	def test_failed_summary_is_rejected_even_when_bench_exits_zero(self):
		self.assert_rejected("Ran 2 tests in 0.100s\n\nFAILED (failures=1)\n")

	def test_nonzero_bench_status_is_propagated_despite_ok_summary(self):
		result = self.run_gate("Ran 2 tests in 0.100s\n\nOK\n", status=7)
		self.assertEqual(result.returncode, 7, result.stdout + result.stderr)

	def test_zero_tests_is_rejected(self):
		self.assert_rejected("Ran 0 tests in 0.000s\n\nOK\n")

	def test_missing_summary_is_rejected(self):
		self.assert_rejected("test output stopped before its runner summary\n")

	def test_earlier_ok_does_not_hide_later_failure(self):
		self.assert_rejected("Ran 1 test in 0.010s\n\nOK\nRan 1 test in 0.010s\n\nFAILED (errors=1)\n")

	def test_ansi_colored_success_is_accepted(self):
		result = self.run_gate("\x1b[32mRan 4 tests in 0.100s\x1b[0m\n\n\x1b[32mOK\x1b[0m\n")
		self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

	def test_interrupted_or_unrecognized_final_summary_is_rejected(self):
		for summary in ("", "unrecognized result\n"):
			with self.subTest(summary=summary):
				self.assert_rejected("Ran 1 test in 0.010s\n\nOK\nRan 2 tests in 0.100s\n\n" + summary)


if __name__ == "__main__":
	unittest.main()
