# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Concurrency armor for the lockout invariant (``passkey_only_login = 1 ⇒
≥1 enabled credential``).

Two overlapping ``delete_credential`` requests used to lock a passkey-only user
out: under InnoDB REPEATABLE READ each request's guard counted the pre-delete
snapshot (two enabled credentials), both guards passed, and both deletes
committed — reproduced live with rapid retry clicks. The mirror race exists on
the flag side (enable ``passkey_only_login`` while the last credential's delete
is in flight). The fix serializes every writer of the invariant on one lock
object — the user's ``WebAuthn User Handle`` row, ``FOR UPDATE`` — and re-checks
against **locking** reads (``lock_login_floor``).

Battery: a true two-connection proof that the guard queues on the handle-row
lock (blocks while a foreign transaction holds it, proceeds once released), and
query-capture checks that every writer issues the locking reads — pinned this
way because the REPEATABLE READ subtlety is invisible to sequential outcome
tests: a plain ``count``/``exists`` after the lock still returns the
transaction's old snapshot.
"""

import hashlib
import queue
import threading
import time

import frappe
from frappe.utils import cint

from passkeys import session, state
from passkeys.api import credentials
from passkeys.passkeys.doctype.webauthn_user_handle.webauthn_user_handle import (
	lock_passkey_mode_floor,
)
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_credential, make_handle, make_user


class _SweptBase(IntegrationTestCase):
	"""Base with a force-sweep tearDown: this module both commits mid-test (the
	foreign connection must see the rows) and turns ``passkey_only_login`` on,
	and the framework's per-class rollback only covers UNCOMMITTED rows — a
	mid-test commit makes a flagged handle durable, and a stray flagged row
	breaks a later module's last-login-method guard (which lists it and refuses
	the save). Sweep and commit, mirroring test_passkey_only_veto."""

	def setUp(self):
		super().setUp()
		self._mode_snapshot = (
			frappe.db.get_single_value("Passkey Settings", "login_with_passkey"),
			frappe.db.get_single_value("Passkey Settings", "passkey_as_second_factor"),
		)
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 1)
		frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
		self.addCleanup(frappe.set_user, "Administrator")

	def tearDown(self):
		super().tearDown()
		frappe.set_user("Administrator")
		frappe.db.sql("delete from `tabWebAuthn Credential` where user like 'passkey-test-%%'")
		frappe.db.sql("delete from `tabWebAuthn User Handle` where user like 'passkey-test-%%'")
		for user in frappe.get_all("User", filters={"email": ["like", "passkey-test-%"]}, pluck="name"):
			frappe.delete_doc("User", user, force=1, ignore_permissions=True, delete_permanently=True)
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", cint(self._mode_snapshot[0]))
		frappe.db.set_single_value(
			"Passkey Settings", "passkey_as_second_factor", cint(self._mode_snapshot[1])
		)
		frappe.db.commit()


class CoreTwoFactorFloorRaceTest(IntegrationTestCase):
	"""Concurrent settings saves cannot commit core-2FA-off/passkey-2FA-on."""

	def setUp(self):
		super().setUp()
		self.site = frappe.local.site
		self.sites_path = frappe.local.sites_path
		self.passkey_snapshot = frappe.db.get_singles_dict("Passkey Settings")
		self.core_snapshot = frappe.db.get_single_value("System Settings", "enable_two_factor_auth")
		frappe.db.set_single_value("System Settings", "enable_two_factor_auth", 1)
		frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
		frappe.db.set_single_value("Passkey Settings", "passkey_rp_id", "example.com")
		frappe.db.set_single_value("Passkey Settings", "passkey_origins", "https://example.com")
		frappe.db.commit()

	def tearDown(self):
		super().tearDown()
		frappe.db.set_single_value("System Settings", "enable_two_factor_auth", cint(self.core_snapshot))
		for field in ("passkey_as_second_factor", "passkey_rp_id", "passkey_origins"):
			# Text singles must not be restored as the truthy string "0".
			default = "" if field in {"passkey_rp_id", "passkey_origins"} else 0
			frappe.db.set_single_value("Passkey Settings", field, self.passkey_snapshot.get(field) or default)
		frappe.db.commit()

	def test_forward_and_reverse_saves_serialize_on_core_flag(self):
		barrier = threading.Barrier(2)
		outcomes = queue.Queue()

		def save(kind: str):
			frappe.init(self.site, sites_path=self.sites_path)
			frappe.connect()
			try:
				if kind == "passkey":
					doc = frappe.get_doc("Passkey Settings")
					doc.passkey_as_second_factor = 1
				else:
					doc = frappe.get_doc("System Settings")
					doc.enable_two_factor_auth = 0
				frappe.db.rollback()
				barrier.wait(timeout=10)
				doc.save(ignore_permissions=True)
				frappe.db.commit()
				outcomes.put((kind, "success"))
			except (frappe.ValidationError, frappe.QueryDeadlockError):
				frappe.db.rollback()
				outcomes.put((kind, "rejected"))
			except Exception as exc:
				frappe.db.rollback()
				outcomes.put((kind, f"error: {exc!r}"))
			finally:
				frappe.destroy()

		threads = [threading.Thread(target=save, args=(kind,)) for kind in ("passkey", "core")]
		for thread in threads:
			thread.start()
		for thread in threads:
			thread.join(timeout=20)

		self.assertFalse(any(thread.is_alive() for thread in threads), "2FA floor race deadlocked")
		results = [outcomes.get_nowait() for _thread in threads]
		self.assertEqual(sorted(status for _kind, status in results), ["rejected", "success"], results)
		core_on = cint(frappe.db.get_single_value("System Settings", "enable_two_factor_auth"))
		passkey_on = cint(frappe.db.get_single_value("Passkey Settings", "passkey_as_second_factor"))
		self.assertFalse(passkey_on and not core_on, results)


class HandleLockSerializationTest(_SweptBase):
	"""Cross-connection serialization: the delete guard must queue on the
	handle-row lock held by another transaction — never read past it."""

	def _foreign_connection(self):
		"""A second, independent DB session (raw driver — deliberately outside
		``frappe.db``) so the lock contention is real, not same-connection
		re-entrancy."""
		import pymysql

		conf = frappe.conf
		kwargs = {
			"user": conf.db_user or conf.db_name,
			"password": conf.db_password,
			"database": conf.db_name,
		}
		if conf.db_socket:
			kwargs["unix_socket"] = conf.db_socket
		else:
			kwargs["host"] = conf.db_host or "127.0.0.1"
			kwargs["port"] = cint(conf.db_port) or 3306
		return pymysql.connect(**kwargs)

	def test_delete_guard_queues_on_a_held_handle_row_lock(self):
		user = make_user()
		keep = make_credential(user)
		drop = make_credential(user)
		make_handle(user)
		frappe.db.commit()  # durable + visible to the foreign transaction

		foreign = self._foreign_connection()
		self.addCleanup(foreign.close)
		try:
			foreign.begin()
			with foreign.cursor() as cursor:
				cursor.execute(
					"select `name` from `tabWebAuthn User Handle` where `user` = %s for update", (user,)
				)
				self.assertEqual(cursor.rowcount, 1)

			frappe.set_user(user)
			state.set_sudo_window(
				frappe.session.sid, {"v": 1, "user": user, "seeded_by": "password"}, ttl=600
			)
			frappe.db.sql("set session innodb_lock_wait_timeout = 1")
			try:
				# while the foreign transaction holds the lock object, the guard
				# BLOCKS (surfacing here as a lock-wait timeout) instead of
				# reading a stale census and waving the delete through.
				with self.assertRaises(frappe.QueryTimeoutError):
					credentials.delete_credential(drop.name)
			finally:
				frappe.db.sql("set session innodb_lock_wait_timeout = default")
			self.assertTrue(frappe.db.exists("WebAuthn Credential", drop.name))
		finally:
			foreign.rollback()  # release the lock

		# lock released → the identical delete proceeds, guard intact
		credentials.delete_credential(drop.name)
		self.assertFalse(frappe.db.exists("WebAuthn Credential", drop.name))
		self.assertTrue(frappe.db.exists("WebAuthn Credential", keep.name))

	def test_mode_floor_lock_returns_the_foreign_connections_committed_values(self):
		"""After waiting on a foreign writer, return that writer's committed values."""
		frappe.db.commit()
		foreign = self._foreign_connection()
		self.addCleanup(foreign.close)
		foreign.begin()
		with foreign.cursor() as cursor:
			cursor.execute(
				"select `value` from `tabSingles` where `doctype` = %s and `field` = %s",
				("Passkey Settings", "login_with_passkey"),
			)
			self.assertEqual(cint(cursor.fetchone()[0]), 1)
			cursor.execute(
				"update `tabSingles` set `value` = 0 where `doctype` = %s and `field` in (%s, %s)",
				("Passkey Settings", "login_with_passkey", "passkey_as_second_factor"),
			)

		# Hold the mode rows long enough for the app connection's FOR UPDATE to
		# queue, then commit from the owning connection. This is the actual race
		# shape: the returned values must come from the locking read after the wait.
		releaser = threading.Thread(target=lambda: (time.sleep(0.2), foreign.commit()))
		releaser.start()
		started = time.monotonic()
		try:
			self.assertFalse(lock_passkey_mode_floor())
		finally:
			releaser.join(timeout=2)
		self.assertGreaterEqual(time.monotonic() - started, 0.15)


class LockingReadTest(_SweptBase):
	"""Every writer of the invariant issues ``FOR UPDATE`` reads on both the
	handle row (the shared lock object) and the credential census."""

	def setUp(self):
		super().setUp()
		self.captured = []
		original_sql = frappe.db.sql

		def spy(query, *args, **kwargs):
			self.captured.append(str(query))
			return original_sql(query, *args, **kwargs)

		frappe.db.sql = spy
		self.addCleanup(setattr, frappe.db, "sql", original_sql)

	@property
	def sid(self) -> str:
		return frappe.session.sid

	def _user(self) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		return user

	def _locking_reads(self) -> list[str]:
		return [query for query in self.captured if "for update" in query.lower()]

	def _assert_locking_read(self, table: str):
		hits = [query for query in self._locking_reads() if table in query]
		self.assertTrue(hits, f"no FOR UPDATE read on {table}; locking reads seen: {self._locking_reads()}")

	def _authorize_toggle(self, user: str, enabled: bool = True) -> None:
		token = frappe.generate_hash()
		state.store_grant(
			hashlib.sha256(token.encode()).hexdigest(),
			{
				"v": 1,
				"user": user,
				"sid": self.sid,
				"action": session.SET_PASSKEY_ONLY_ACTION,
				"method": "passkey",
				"payload_hash": session.payload_hash({"enabled": enabled}),
			},
		)
		frappe.local.form_dict[session.GRANT_KWARG] = token

	def test_endpoint_delete_guard_uses_locking_reads(self):
		user = self._user()
		make_credential(user)
		drop = make_credential(user)
		make_handle(user)
		frappe.set_user(user)
		state.set_sudo_window(self.sid, {"v": 1, "user": user, "seeded_by": "password"}, ttl=600)
		self.captured.clear()
		credentials.delete_credential(drop.name)
		self._assert_locking_read("tabWebAuthn User Handle")
		self._assert_locking_read("tabWebAuthn Credential")

	def test_disable_save_guard_uses_locking_reads(self):
		user = self._user()
		make_credential(user)
		doc = make_credential(user)
		make_handle(user, passkey_only_login=1)
		doc.enabled = 0
		self.captured.clear()
		doc.save(ignore_permissions=True)
		self._assert_locking_read("tabWebAuthn User Handle")
		self._assert_locking_read("tabWebAuthn Credential")

	def test_passkey_only_toggle_uses_locking_reads(self):
		user = self._user()
		make_credential(user)
		make_credential(user)
		make_handle(user)
		frappe.set_user(user)
		self._authorize_toggle(user)
		self.captured.clear()
		credentials.set_passkey_only_login(1)
		self._assert_locking_read("tabSingles")
		self._assert_locking_read("tabWebAuthn User Handle")
		self._assert_locking_read("tabWebAuthn Credential")

	def test_handle_floor_uses_locking_reads(self):
		user = self._user()
		make_credential(user)
		handle = make_handle(user)
		handle.passkey_only_login = 1
		self.captured.clear()
		handle.save(ignore_permissions=True)
		self._assert_locking_read("tabSingles")
		self._assert_locking_read("tabWebAuthn User Handle")
		self._assert_locking_read("tabWebAuthn Credential")

	def test_settings_mode_off_guard_uses_shared_lock(self):
		user = self._user()
		make_credential(user)
		make_handle(user, passkey_only_login=1)
		settings = frappe.get_doc("Passkey Settings")
		settings.login_with_passkey = 0
		settings.passkey_as_second_factor = 0
		self.captured.clear()
		with self.assertRaises(frappe.ValidationError):
			settings.save(ignore_permissions=True)
		self._assert_locking_read("tabSingles")
		self._assert_locking_read("tabWebAuthn User Handle")

	def test_toggle_refuses_when_both_passkey_modes_are_off(self):
		user = self._user()
		make_credential(user)
		make_credential(user)
		make_handle(user)
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 0)
		frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
		frappe.set_user(user)
		self._authorize_toggle(user)
		with self.assertRaises(frappe.ValidationError):
			credentials.set_passkey_only_login(1)

	def test_direct_handle_save_refuses_when_both_passkey_modes_are_off(self):
		user = self._user()
		make_credential(user)
		handle = make_handle(user)
		frappe.db.set_single_value("Passkey Settings", "login_with_passkey", 0)
		frappe.db.set_single_value("Passkey Settings", "passkey_as_second_factor", 0)
		handle.passkey_only_login = 1
		with self.assertRaises(frappe.ValidationError):
			handle.save(ignore_permissions=True)
