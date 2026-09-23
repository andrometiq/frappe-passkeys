# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Concurrency coverage for incapable-advisory delivery and its durable marker."""

import queue
import threading
import traceback
from unittest.mock import patch

import frappe

from passkeys import notifications
from passkeys.install import DEFAULTS_PARENT
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_user


class IncapableNotificationConcurrencyTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self.user = make_user()
		self.site = frappe.local.site
		self.sites_path = frappe.local.sites_path
		frappe.db.commit()  # independent workers must see the shared User lock row

	def tearDown(self):
		super().tearDown()
		frappe.set_user("Administrator")
		frappe.db.delete(
			"DefaultValue",
			{"parent": DEFAULTS_PARENT, "defkey": notifications.incapable_notify_key(self.user)},
		)
		frappe.delete_doc("User", self.user, force=1, ignore_permissions=True, delete_permanently=True)
		frappe.db.commit()

	def _marker(self):
		return frappe.db.get_value(
			"DefaultValue",
			{"parent": DEFAULTS_PARENT, "defkey": notifications.incapable_notify_key(self.user)},
			"defvalue",
		)

	def test_concurrent_first_reports_send_one_advisory(self):
		barrier = threading.Barrier(2)
		outcomes = queue.Queue()
		first_send_started = threading.Event()
		release_first_send = threading.Event()
		second_send_started = threading.Event()
		send_count = 0
		send_count_lock = threading.Lock()

		def sendmail(**_kwargs):
			nonlocal send_count
			with send_count_lock:
				send_count += 1
				call_number = send_count
			if call_number == 1:
				first_send_started.set()
				release_first_send.wait(timeout=5)
			else:
				second_send_started.set()

		def report():
			frappe.init(self.site, sites_path=self.sites_path)
			frappe.connect()
			try:
				frappe.db.rollback()
				# Establish an absent-marker snapshot before the race. The production
				# check must be a locking read after the User lock, not this stale view.
				frappe.db.get_value(
					"DefaultValue",
					{"parent": DEFAULTS_PARENT, "defkey": notifications.incapable_notify_key(self.user)},
					"defvalue",
				)
				barrier.wait(timeout=10)
				notifications.record_enforcement_incapable(self.user)
				frappe.db.commit()
				outcomes.put("success")
			except Exception as exc:
				frappe.db.rollback()
				outcomes.put(f"error: {exc!r}\n{traceback.format_exc()}")
			finally:
				frappe.destroy()

		with (
			patch.object(notifications, "_activity_log"),
			patch.object(notifications, "_system_manager_emails", return_value=["mgr@example.com"]),
			patch("frappe.sendmail", side_effect=sendmail),
		):
			threads = [threading.Thread(target=report) for _ in range(2)]
			for thread in threads:
				thread.start()
			first_started = first_send_started.wait(timeout=10)
			if first_started:
				second_send_started.wait(timeout=1)
			release_first_send.set()
			for thread in threads:
				thread.join(timeout=20)

		self.assertTrue(first_started, "first advisory did not start")
		self.assertFalse(any(thread.is_alive() for thread in threads), "notification race deadlocked")
		results = [outcomes.get_nowait() for _thread in threads]
		self.assertEqual(results, ["success", "success"], results)
		self.assertEqual(send_count, 1)
		self.assertIsNotNone(self._marker())

	def test_send_failure_leaves_no_marker_and_a_later_report_retries(self):
		with (
			patch.object(notifications, "_activity_log"),
			patch.object(notifications, "_system_manager_emails", return_value=["mgr@example.com"]),
			patch("frappe.log_error"),
			patch("frappe.sendmail", side_effect=[RuntimeError("mail unavailable"), None]) as sendmail,
		):
			notifications.record_enforcement_incapable(self.user)
			self.assertIsNone(self._marker())
			notifications.record_enforcement_incapable(self.user)
		self.assertEqual(sendmail.call_count, 2)
		self.assertIsNotNone(self._marker())

	def test_no_managers_leaves_no_marker_and_a_later_report_retries(self):
		with (
			patch.object(notifications, "_activity_log"),
			patch.object(
				notifications,
				"_system_manager_emails",
				side_effect=[[], ["mgr@example.com"]],
			),
			patch("frappe.sendmail") as sendmail,
		):
			notifications.record_enforcement_incapable(self.user)
			self.assertIsNone(self._marker())
			notifications.record_enforcement_incapable(self.user)
		self.assertEqual(sendmail.call_count, 1)
		self.assertIsNotNone(self._marker())
