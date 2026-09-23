# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Two-connection interleavings of Passkey Settings and System Settings saves that
must not together break a login floor."""

import queue
import threading
import traceback

import frappe
from frappe.utils import cint

from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache

PASSKEY_FIELDS = ("login_with_passkey", "passkey_as_second_factor", "passkey_rp_id", "passkey_origins")
SYSTEM_FIELDS = ("enable_two_factor_auth", "disable_user_pass_login", "login_with_email_link")
TEXT_FIELDS = ("passkey_rp_id", "passkey_origins")


def disable_passwordless(docs):
	docs["Passkey Settings"].login_with_passkey = 0
	docs["Passkey Settings"].save(ignore_permissions=True)


def disable_password_login(docs):
	docs["System Settings"].disable_user_pass_login = 1
	docs["System Settings"].save(ignore_permissions=True)


def enable_second_factor(docs):
	docs["Passkey Settings"].passkey_as_second_factor = 1
	docs["Passkey Settings"].save(ignore_permissions=True)


def disable_two_factor(docs):
	docs["System Settings"].enable_two_factor_auth = 0
	docs["System Settings"].save(ignore_permissions=True)


class SettingsFloorConcurrencyTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self.site = frappe.local.site
		self.sites_path = frappe.local.sites_path
		self._passkey_snapshot = {
			f: frappe.db.get_single_value("Passkey Settings", f) for f in PASSKEY_FIELDS
		}
		self._system_snapshot = {f: frappe.db.get_single_value("System Settings", f) for f in SYSTEM_FIELDS}

	def tearDown(self):
		super().tearDown()
		self._arrange(
			passkey={f: self._passkey_snapshot[f] or ("" if f in TEXT_FIELDS else 0) for f in PASSKEY_FIELDS},
			system={f: cint(self._system_snapshot[f]) for f in SYSTEM_FIELDS},
		)

	def _arrange(self, *, passkey, system):
		for field, value in passkey.items():
			frappe.db.set_single_value("Passkey Settings", field, value)
		for field, value in system.items():
			frappe.db.set_single_value("System Settings", field, value)
		frappe.db.commit()  # independent workers must see the arranged rows
		flush_settings_cache()
		frappe.clear_document_cache("System Settings", "System Settings")
		frappe.local.system_settings = None

	def _arrange_both_modes_on(self, **overrides):
		# email-link login keeps core's own "a login method must remain" check satisfied
		self._arrange(
			passkey={
				"login_with_passkey": 1,
				"passkey_as_second_factor": 1,
				"passkey_rp_id": "example.com",
				"passkey_origins": "https://example.com",
				**overrides,
			},
			system={"enable_two_factor_auth": 1, "disable_user_pass_login": 0, "login_with_email_link": 1},
		)

	def _interleave(self, first, second) -> list[str]:
		"""Run ``second``'s save after ``first`` committed on another connection,
		with ``second``'s REPEATABLE READ snapshot pinned before that commit: a
		validator that trusts the snapshot instead of a locked current read
		approves a combination the first save already made unsafe."""
		is_pinned, is_first_done = threading.Event(), threading.Event()
		outcomes = queue.Queue()

		def run(writer, *, before_write, after_write):
			frappe.init(self.site, sites_path=self.sites_path)
			frappe.connect()
			try:
				if frappe.db.sql("show variables like 'innodb_snapshot_isolation'"):
					frappe.db.sql("set session innodb_snapshot_isolation = OFF")
				frappe.db.rollback()
				docs = {
					doctype: frappe.get_doc(doctype) for doctype in ("Passkey Settings", "System Settings")
				}
				before_write()
				writer(docs)
				frappe.db.commit()
				outcomes.put((writer.__name__, "success"))
			except frappe.ValidationError as exc:
				frappe.db.rollback()
				outcomes.put((writer.__name__, f"refused: {exc}"))
			except Exception as exc:
				frappe.db.rollback()
				outcomes.put((writer.__name__, f"error: {exc!r}\n{traceback.format_exc()}"))
			finally:
				after_write()
				frappe.destroy()

		threads = [
			threading.Thread(
				target=run,
				args=(first,),
				kwargs={"before_write": lambda: is_pinned.wait(10), "after_write": is_first_done.set},
			),
			threading.Thread(
				target=run,
				args=(second,),
				kwargs={
					"before_write": lambda: (is_pinned.set(), is_first_done.wait(10)),
					"after_write": lambda: None,
				},
			),
		]
		for thread in threads:
			thread.start()
		for thread in threads:
			thread.join(timeout=30)
		self.assertFalse(any(thread.is_alive() for thread in threads), "interleaving deadlocked")
		frappe.db.rollback()  # drop this connection's snapshot before reading the result
		results = dict(outcomes.get_nowait() for _thread in threads)
		return [results[first.__name__], results[second.__name__]]

	def test_password_login_floor_holds_across_connections(self):
		for first, second in (
			(disable_passwordless, disable_password_login),
			(disable_password_login, disable_passwordless),
		):
			with self.subTest(first=first.__name__):
				self._arrange_both_modes_on()
				first_result, second_result = self._interleave(first, second)
				self.assertEqual(first_result, "success")
				self.assertTrue(second_result.startswith("refused"), second_result)
				self.assertIn("only passkey mode", second_result)

	def test_two_factor_floor_holds_across_connections(self):
		for first, second in (
			(enable_second_factor, disable_two_factor),
			(disable_two_factor, enable_second_factor),
		):
			with self.subTest(first=first.__name__):
				self._arrange_both_modes_on(passkey_as_second_factor=0)
				first_result, second_result = self._interleave(first, second)
				self.assertEqual(first_result, "success")
				self.assertTrue(second_result.startswith("refused"), second_result)
				self.assertIn("Two Factor Authentication", second_result)
