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

import frappe
from frappe.utils import cint

from passkeys import session, state
from passkeys.api import credentials
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
		self.addCleanup(frappe.set_user, "Administrator")

	def tearDown(self):
		super().tearDown()
		frappe.set_user("Administrator")
		frappe.db.sql("delete from `tabWebAuthn Credential` where user like 'passkey-test-%%'")
		frappe.db.sql("delete from `tabWebAuthn User Handle` where user like 'passkey-test-%%'")
		for user in frappe.get_all("User", filters={"email": ["like", "passkey-test-%"]}, pluck="name"):
			frappe.delete_doc("User", user, force=1, ignore_permissions=True, delete_permanently=True)
		frappe.db.commit()


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
		token = frappe.generate_hash()
		state.store_grant(
			hashlib.sha256(token.encode()).hexdigest(),
			{
				"v": 1,
				"user": user,
				"sid": self.sid,
				"action": session.SET_PASSKEY_ONLY_ACTION,
				"method": "passkey",
				"payload_hash": session.payload_hash({"enabled": True}),
			},
		)
		frappe.local.form_dict[session.GRANT_KWARG] = token
		self.captured.clear()
		credentials.set_passkey_only_login(1)
		self._assert_locking_read("tabWebAuthn User Handle")
		self._assert_locking_read("tabWebAuthn Credential")

	def test_handle_floor_uses_locking_reads(self):
		user = self._user()
		make_credential(user)
		handle = make_handle(user)
		handle.passkey_only_login = 1
		self.captured.clear()
		handle.save(ignore_permissions=True)
		self._assert_locking_read("tabWebAuthn User Handle")
		self._assert_locking_read("tabWebAuthn Credential")
