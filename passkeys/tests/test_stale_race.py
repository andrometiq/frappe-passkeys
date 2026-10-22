# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Competing transactions for the bulk-removal settings lock."""

import queue
import threading
from unittest.mock import patch

import frappe

from passkeys import policy, rp_admin, state
from passkeys.api.credentials import delete_credential
from passkeys.passkeys.doctype.passkey_settings.passkey_settings import remove_stale_passkeys
from passkeys.tests import committed_state
from passkeys.tests.compat import IntegrationTestCase, flush_settings_cache
from passkeys.tests.factories import make_credential, make_handle, make_user, sign_in


class StaleRemovalRaceTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		sign_in("Administrator")
		self.baseline = committed_state.capture()
		self.assertFalse(
			self.baseline["WebAuthn Credential"],
			"Bulk-removal races require a site without pre-existing credentials",
		)
		self.site, self.sites_path = frappe.local.site, frappe.local.sites_path
		self.threads = []
		self.releases = []
		self.outcomes = queue.Queue()
		self.host_name = frappe.conf.get("host_name")
		frappe.conf.host_name = "https://example.com"
		frappe.db.set_single_value(
			"Passkey Settings",
			{
				"passkey_rp_id": "example.com",
				"passkey_origins": "https://example.com",
				"passkey_app_origins": "",
				"login_with_passkey": 1,
				"passkey_as_second_factor": 0,
				"passkey_notify_on_change": 1,
			},
		)
		flush_settings_cache()
		self.user = make_user()
		make_handle(self.user)
		self.current = make_credential(self.user)
		self.stale = make_credential(self.user, rp_id="other.example")
		frappe.db.commit()
		self.rate_key = f"{state.RATE_LIMIT_PREFIX}remove_stale_passkeys:Administrator"
		state.clear_counter(self.rate_key)

	def tearDown(self):
		try:
			for release in self.releases:
				release.set()
			for thread in self.threads:
				thread.join(timeout=15)
			self.assertFalse(any(thread.is_alive() for thread in self.threads), "Race worker deadlocked")
			sign_in("Administrator")
			committed_state.restore(self.baseline, self.id())
		finally:
			frappe.conf.host_name = self.host_name
			state.clear_counter(self.rate_key)
			state.clear_counter(f"{state.RATE_LIMIT_PREFIX}delete_credential:{self.user}")
			super().tearDown()

	def release_event(self):
		event = threading.Event()
		self.releases.append(event)
		return event

	def wait_for(self, event):
		self.assertTrue(event.wait(timeout=10), "Race synchronization timed out")

	def start_worker(self, name, operation):
		done = threading.Event()

		def run():
			frappe.init(self.site, sites_path=self.sites_path)
			frappe.connect()
			try:
				frappe.conf.host_name = "https://example.com"
				frappe.flags.in_test = True
				sign_in("Administrator")
				frappe.db.sql("set session innodb_lock_wait_timeout = 5")
				if frappe.db.sql("show session variables like 'innodb_snapshot_isolation'"):
					frappe.db.sql("set session innodb_snapshot_isolation = OFF")
				frappe.db.sql("set session transaction isolation level repeatable read")
				frappe.db.rollback()
				result = operation()
				frappe.db.commit()
				self.outcomes.put((name, result))
			except Exception as exc:
				frappe.db.rollback()
				self.outcomes.put((name, exc))
			finally:
				frappe.destroy()
				done.set()

		thread = threading.Thread(target=run, name=name, daemon=True)
		self.threads.append(thread)
		thread.start()
		return done

	def results(self):
		for thread in self.threads:
			thread.join(timeout=15)
		self.assertFalse(any(thread.is_alive() for thread in self.threads), "Race worker deadlocked")
		self.assertEqual(self.outcomes.qsize(), len(self.threads))
		frappe.db.rollback()
		flush_settings_cache()
		return dict(self.outcomes.get_nowait() for _ in self.threads)

	def save_other_rp(self):
		doc = frappe.get_doc("Passkey Settings")
		doc.passkey_rp_id = "other.example"
		doc.passkey_origins = "https://other.example"
		doc.save(ignore_permissions=True)
		return "saved"

	def test_bulk_first_holds_settings_save_until_removal_commits(self):
		locked, save_started = threading.Event(), threading.Event()
		release = self.release_event()
		lock = rp_admin.lock_passkey_modes

		def hold_bulk_lock():
			settings = lock()
			locked.set()
			self.wait_for(release)
			return settings

		def save_observing_singles_lock():
			# Core's save locks the Single first (load_doc_before_save → get_doc(for_update=True)),
			# before Passkey Settings.validate reaches lock_passkey_modes; signal on whichever
			# locking read of tabSingles the save issues first.
			db = frappe.local.db
			sql = db.sql

			def observe(query, *args, **kwargs):
				text = str(query).lower()
				if "tabsingles" in text and "for update" in text:
					save_started.set()
				return sql(query, *args, **kwargs)

			with patch.object(db, "sql", side_effect=observe):
				return self.save_other_rp()

		with (
			patch.object(rp_admin, "lock_passkey_modes", side_effect=hold_bulk_lock),
			patch.object(frappe, "enqueue"),
		):
			self.start_worker("bulk", lambda: remove_stale_passkeys("example.com"))
			try:
				self.wait_for(locked)
				saved = self.start_worker("save", save_observing_singles_lock)
				self.wait_for(save_started)
				self.assertFalse(saved.wait(timeout=0.2), "Settings save passed the held Singles lock")
			finally:
				release.set()
			results = self.results()
		self.assertEqual(results, {"bulk": {"removed": 1}, "save": "saved"})
		self.assertEqual(policy.get_site_rp_id(policy.read_rp_settings()), "other.example")
		self.assertFalse(frappe.db.exists("WebAuthn Credential", self.stale.name))
		self.assertTrue(frappe.db.exists("WebAuthn Credential", self.current.name))

	def test_save_first_bulk_reads_current_locked_rp_despite_old_snapshot(self):
		cached, saved, attempted = threading.Event(), threading.Event(), threading.Event()
		start_bulk, commit_save = self.release_event(), self.release_event()
		lock = rp_admin.lock_passkey_modes

		def observe_bulk_lock():
			attempted.set()
			return lock()

		def bulk():
			self.assertEqual(policy.get_site_rp_id(), "example.com")
			self.assertEqual(policy.read_rp_settings()["passkey_rp_id"], "example.com")
			cached.set()
			self.wait_for(start_bulk)
			return remove_stale_passkeys("example.com")

		def save():
			result = self.save_other_rp()
			saved.set()
			self.wait_for(commit_save)
			return result

		with (
			patch.object(rp_admin, "lock_passkey_modes", side_effect=observe_bulk_lock),
			patch.object(frappe, "enqueue"),
		):
			bulk_done = self.start_worker("bulk", bulk)
			try:
				self.wait_for(cached)
				self.start_worker("save", save)
				self.wait_for(saved)
				start_bulk.set()
				self.wait_for(attempted)
				self.assertFalse(bulk_done.wait(timeout=0.2), "Bulk passed the save's Singles lock")
			finally:
				start_bulk.set()
				commit_save.set()
			results = self.results()
		self.assertEqual(results["save"], "saved")
		self.assertIsInstance(results["bulk"], frappe.ValidationError)
		self.assertIn("The RP ID changed since this page loaded", str(results["bulk"]))
		for row in (self.current, self.stale):
			self.assertTrue(frappe.db.exists("WebAuthn Credential", row.name))

	def test_owner_delete_wins_selected_bulk_row_without_deadlock_or_second_email(self):
		selected = threading.Event()
		release = self.release_event()
		select = rp_admin.stale_credentials

		def hold_selection(site_rp_id):
			rows = select(site_rp_id)
			self.assertIn(self.stale.name, [row.name for row in rows])
			selected.set()
			self.wait_for(release)
			return rows

		def owner_delete():
			sign_in(self.user)
			sid = frappe.session.sid
			state.set_sudo_window(sid, {"v": 1, "user": self.user, "seeded_by": "password"}, ttl=600)
			try:
				return delete_credential(self.stale.name)
			finally:
				state.clear_sudo_window(sid)

		with (
			patch.object(rp_admin, "stale_credentials", side_effect=hold_selection),
			patch.object(frappe, "sendmail") as mail,
		):
			self.start_worker("bulk", lambda: remove_stale_passkeys("example.com"))
			try:
				self.wait_for(selected)
				owner_done = self.start_worker("owner", owner_delete)
				self.wait_for(owner_done)
			finally:
				release.set()
			results = self.results()
		self.assertEqual(results, {"bulk": {"removed": 0}, "owner": {"deleted": self.stale.name}})
		self.assertFalse(frappe.db.exists("WebAuthn Credential", self.stale.name))
		self.assertTrue(frappe.db.exists("WebAuthn Credential", self.current.name))
		self.assertEqual(mail.call_count, 1)
		self.assertEqual(mail.call_args.kwargs["recipients"], [self.user])
		self.assertEqual(mail.call_args.kwargs["subject"], "A passkey was removed from your account")

	def test_flag_committed_after_selection_keeps_row_without_removal_email(self):
		selected = threading.Event()
		release = self.release_event()
		select = rp_admin.stale_credentials

		def hold_selection(site_rp_id):
			rows = select(site_rp_id)
			self.assertIn(self.stale.name, [row.name for row in rows if not row.flagged])
			selected.set()
			self.wait_for(release)
			return rows

		with (
			patch.object(rp_admin, "stale_credentials", side_effect=hold_selection),
			patch.object(frappe, "sendmail") as mail,
		):
			self.start_worker("bulk", lambda: remove_stale_passkeys("example.com"))
			try:
				self.wait_for(selected)
				frappe.db.rollback()
				frappe.db.set_value("WebAuthn Credential", self.stale.name, "flagged", 1)
				frappe.db.commit()
			finally:
				release.set()
			results = self.results()
		self.assertEqual(results, {"bulk": {"removed": 0}})
		self.assertEqual(frappe.db.get_value("WebAuthn Credential", self.stale.name, "flagged"), 1)
		self.assertTrue(frappe.db.exists("WebAuthn Credential", self.current.name))
		mail.assert_not_called()
