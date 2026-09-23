# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Two-connection races on the per-user nudge and grace counters."""

import queue
import threading
import traceback

import frappe

from passkeys import boot
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_user


class NudgeStateConcurrencyTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self.user = make_user()
		self.site = frappe.local.site
		self.sites_path = frappe.local.sites_path
		frappe.db.commit()  # independent workers must see the shared User lock row

	def tearDown(self):
		super().tearDown()
		frappe.set_user("Administrator")
		boot.clear_user_state(self.user)
		frappe.delete_doc("User", self.user, force=1, ignore_permissions=True, delete_permanently=True)
		frappe.db.commit()

	def _race(self, *writers):
		"""Run each writer on its own connection. Each worker first reads the row
		without locking, pinning its REPEATABLE READ snapshot to the pre-race state:
		a writer that folds into that snapshot instead of a locked current read loses
		the other worker's update. ``innodb_snapshot_isolation`` (MariaDB ≥ 11.8
		default) is switched off per session so the engine does not turn that lost
		update into an error and hide it."""
		barrier = threading.Barrier(len(writers))
		outcomes = queue.Queue()

		def run(writer):
			frappe.init(self.site, sites_path=self.sites_path)
			frappe.connect()
			try:
				if frappe.db.sql("show variables like 'innodb_snapshot_isolation'"):
					frappe.db.sql("set session innodb_snapshot_isolation = OFF")
				frappe.db.rollback()
				for key in boot.get_user_state_keys(self.user):
					boot.get_default_value(key)
				barrier.wait(timeout=10)
				writer()
				frappe.db.commit()
				outcomes.put("success")
			except Exception as exc:
				frappe.db.rollback()
				outcomes.put(f"error: {exc!r}\n{traceback.format_exc()}")
			finally:
				frappe.destroy()

		threads = [threading.Thread(target=run, args=(writer,)) for writer in writers]
		for thread in threads:
			thread.start()
		for thread in threads:
			thread.join(timeout=20)
		self.assertFalse(any(thread.is_alive() for thread in threads), "race deadlocked")
		results = [outcomes.get_nowait() for _thread in threads]
		self.assertEqual(results, ["success"] * len(writers), results)
		frappe.db.rollback()  # drop this connection's snapshot before reading the result

	def test_shown_racing_opt_out_keeps_both(self):
		boot.record_nudge_event(self.user, "declined")  # an existing row to race on
		frappe.db.commit()
		self._race(
			lambda: boot.record_nudge_event(self.user, "shown"),
			lambda: boot.record_nudge_event(self.user, "opt_out"),
		)
		state = boot.get_nudge_state(self.user)
		self.assertEqual((state["declines"], state["opt_out"]), (1, 1))

	def test_concurrent_defers_spend_two_grace_logins(self):
		boot.record_enforcement_defer(self.user)
		frappe.db.commit()
		self._race(
			lambda: boot.record_enforcement_defer(self.user),
			lambda: boot.record_enforcement_defer(self.user),
		)
		self.assertEqual(boot.get_enforcement_state(self.user)["grace_used"], 3)
