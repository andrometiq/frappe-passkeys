# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Save-time dependency import probe for passkey mode enablement."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import frappe
from frappe.utils import cint

from passkeys import policy
from passkeys.tests.compat import IntegrationTestCase


class DependencyProbeTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self._settings = frappe.db.get_singles_dict("Passkey Settings")
		self._two_factor_auth = frappe.db.get_single_value("System Settings", "enable_two_factor_auth")
		self._disable_user_pass_login = frappe.db.get_single_value(
			"System Settings", "disable_user_pass_login"
		)
		self._encryption_key = frappe.local.conf.get("encryption_key")
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 0)
		frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
		frappe.db.set_single_value("System Settings", "enable_two_factor_auth", 1)
		frappe.db.set_single_value("System Settings", "disable_user_pass_login", 0)
		frappe.local.conf["encryption_key"] = self._encryption_key or "test-encryption-key"

	def tearDown(self):
		for fieldname in ("login_with_passkey", "passkey_as_second_factor"):
			frappe.db.set_single_value("Passkey Settings", fieldname, self._settings.get(fieldname) or 0)
		for fieldname in ("passkey_rp_id", "passkey_origins"):
			frappe.db.set_single_value("Passkey Settings", fieldname, self._settings.get(fieldname) or "")
		frappe.db.set_single_value("System Settings", "enable_two_factor_auth", cint(self._two_factor_auth))
		frappe.db.set_single_value(
			"System Settings", "disable_user_pass_login", cint(self._disable_user_pass_login)
		)
		frappe.local.conf["encryption_key"] = self._encryption_key
		super().tearDown()

	def _doc(self, **modes):
		doc = frappe.get_doc("Passkey Settings")
		doc.passkey_rp_id = "example.com"
		doc.passkey_origins = "https://example.com"
		doc.update(modes)
		return doc

	def test_each_mode_transition_runs_probe(self):
		for fieldname in ("login_with_passkey", "passkey_as_second_factor"):
			with self.subTest(fieldname=fieldname):
				frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 0)
				frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
				with patch("passkeys.policy.validate_webauthn_importable") as probe:
					self._doc(**{fieldname: 1}).save()
				probe.assert_called_once_with()

	def test_enabling_both_modes_runs_one_probe(self):
		with patch("passkeys.policy.validate_webauthn_importable") as probe:
			self._doc(login_with_passkey=1, passkey_as_second_factor=1).save()
		probe.assert_called_once_with()

	def test_enabling_second_mode_while_first_is_enabled_runs_probe(self):
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 1)
		with patch("passkeys.policy.validate_webauthn_importable") as probe:
			self._doc(login_with_passkey=1, passkey_as_second_factor=1).save()
		probe.assert_called_once_with()

	def test_existing_enabled_save_and_disable_do_not_probe(self):
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 1)
		frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 1)
		with patch("passkeys.policy.validate_webauthn_importable") as probe:
			self._doc(login_with_passkey=1, passkey_as_second_factor=1).save()
			self._doc(login_with_passkey=0, passkey_as_second_factor=1).save()
		probe.assert_not_called()

	def test_transition_uses_persisted_singles_when_before_save_is_unavailable(self):
		doc = self._doc(login_with_passkey=1)
		with (
			patch.object(doc, "get_doc_before_save", return_value=None),
			patch("passkeys.policy.validate_webauthn_importable") as probe,
		):
			doc.validate()
		probe.assert_called_once_with()

	def test_broken_discoverable_dependency_refuses_enablement(self):
		with tempfile.TemporaryDirectory() as directory:
			package = Path(directory) / "webauthn"
			package.mkdir()
			(package / "__init__.py").write_text(
				'raise RuntimeError("broken dependency sentinel")\n', encoding="utf-8"
			)
			pythonpath = directory
			if existing := os.environ.get("PYTHONPATH"):
				pythonpath += os.pathsep + existing
			with patch.dict(os.environ, {"PYTHONPATH": pythonpath}):
				with self.assertRaisesRegex(frappe.ValidationError, "broken dependency sentinel"):
					self._doc(login_with_passkey=1).save()
		self.assertFalse(frappe.db.get_single_value("Passkey Settings", "login_with_passkey"))


class DependencyProbeFailureTest(unittest.TestCase):
	def test_probe_uses_current_interpreter_and_fixed_import(self):
		completed = subprocess.CompletedProcess([], 0, stderr=b"")
		with patch("passkeys.policy.subprocess.run", return_value=completed) as run:
			policy.validate_webauthn_importable()
		run.assert_called_once_with(
			[sys.executable, "-c", "import passkeys.engine"],
			stdin=subprocess.DEVNULL,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.PIPE,
			check=False,
			timeout=policy.WEBAUTHN_IMPORT_TIMEOUT,
		)

	def test_child_start_failure_is_rejected(self):
		with patch("passkeys.policy.subprocess.run", side_effect=OSError("cannot execute")):
			with self.assertRaisesRegex(frappe.ValidationError, "could not start: cannot execute"):
				policy.validate_webauthn_importable()

	def test_timeout_is_rejected_with_stderr(self):
		error = subprocess.TimeoutExpired("python", policy.WEBAUTHN_IMPORT_TIMEOUT, stderr=b"still loading")
		with patch("passkeys.policy.subprocess.run", side_effect=error):
			with self.assertRaisesRegex(frappe.ValidationError, "timed out.*still loading"):
				policy.validate_webauthn_importable()

	def test_nonzero_exit_is_rejected_with_capped_stderr(self):
		stderr = b"x" * policy.WEBAUTHN_IMPORT_STDERR_LIMIT + b"failure tail"
		completed = subprocess.CompletedProcess([], 7, stderr=stderr)
		with patch("passkeys.policy.subprocess.run", return_value=completed):
			with self.assertRaisesRegex(frappe.ValidationError, "status 7.*failure tail") as ctx:
				policy.validate_webauthn_importable()
		self.assertNotIn("x" * policy.WEBAUTHN_IMPORT_STDERR_LIMIT, str(ctx.exception))

	def test_real_probe_keeps_engine_out_of_parent_process(self):
		script = """
import json
import sys
from passkeys import policy

before = {name: name in sys.modules for name in ("passkeys.engine", "webauthn")}
policy.validate_webauthn_importable()
after = {name: name in sys.modules for name in ("passkeys.engine", "webauthn")}
print(json.dumps({"before": before, "after": after}))
"""
		result = subprocess.run(
			[sys.executable, "-c", script],
			cwd=Path(__file__).resolve().parents[2],
			stdin=subprocess.DEVNULL,
			capture_output=True,
			check=False,
			timeout=policy.WEBAUTHN_IMPORT_TIMEOUT + 5,
		)
		self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
		modules = json.loads(result.stdout)
		self.assertEqual(modules["before"], {"passkeys.engine": False, "webauthn": False})
		self.assertEqual(modules["after"], modules["before"])
