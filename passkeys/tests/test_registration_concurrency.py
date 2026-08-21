# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Concurrency coverage for registration's User -> Handle -> Credential locks."""

import base64
import hashlib
import queue
import threading
import traceback

import frappe

from passkeys.api import registration
from passkeys.tests.compat import IntegrationTestCase
from passkeys.tests.factories import make_user


def _credential_doc(user: str, seed: str):
	raw_id = hashlib.sha256(seed.encode()).digest()
	return frappe.get_doc(
		{
			"doctype": "WebAuthn Credential",
			"user": user,
			"label": "Concurrent registration",
			"credential_id": base64.urlsafe_b64encode(raw_id).rstrip(b"=").decode(),
			"credential_id_sha256": hashlib.sha256(raw_id).hexdigest(),
			"public_key": base64.urlsafe_b64encode(hashlib.sha512(raw_id).digest()).rstrip(b"=").decode(),
		}
	)


class RegistrationLockingReadTest(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		self.addCleanup(frappe.set_user, "Administrator")

	def _user(self) -> str:
		user = make_user()
		self.addCleanup(frappe.delete_doc, "User", user, force=1, ignore_permissions=True)
		return user

	def _capture_queries(self):
		captured = []
		original_sql = frappe.db.sql

		def spy(query, *args, **kwargs):
			captured.append(str(query))
			return original_sql(query, *args, **kwargs)

		frappe.db.sql = spy
		self.addCleanup(setattr, frappe.db, "sql", original_sql)
		return captured

	def test_verified_insert_locks_user_handle_and_credential_census_in_order(self):
		user = self._user()
		captured = self._capture_queries()

		registration._insert_verified_credential(
			_credential_doc(user, "lock-order"),
			frappe._dict(passkey_max_per_user=2),
			"explicit",
		)

		locking_reads = [query for query in captured if "for update" in query.lower()]
		positions = {}
		for table in ("tabUser", "tabWebAuthn User Handle", "tabWebAuthn Credential"):
			positions[table] = next(
				(index for index, query in enumerate(locking_reads) if table in query),
				None,
			)
		self.assertTrue(all(position is not None for position in positions.values()), locking_reads)
		self.assertLess(positions["tabUser"], positions["tabWebAuthn User Handle"])
		self.assertLess(positions["tabWebAuthn User Handle"], positions["tabWebAuthn Credential"])

	def test_handle_creation_helper_locks_user_before_handle(self):
		user = self._user()
		captured = self._capture_queries()

		registration._get_or_create_handle(user)

		locking_reads = [query for query in captured if "for update" in query.lower()]
		user_lock = next(index for index, query in enumerate(locking_reads) if "tabUser" in query)
		handle_lock = next(
			index for index, query in enumerate(locking_reads) if "tabWebAuthn User Handle" in query
		)
		self.assertLess(user_lock, handle_lock)


class RegistrationCapRaceTest(IntegrationTestCase):
	"""Two independent connections race registrations through the User lock."""

	def setUp(self):
		super().setUp()
		self.user = make_user()
		registration._get_or_create_handle(self.user)
		self.site = frappe.local.site
		self.sites_path = frappe.local.sites_path
		frappe.db.commit()  # workers must see the User + handle created by begin_registration

	def tearDown(self):
		super().tearDown()
		frappe.set_user("Administrator")
		frappe.db.sql("delete from `tabWebAuthn Credential` where `user` = %s", self.user)
		frappe.db.sql("delete from `tabWebAuthn User Handle` where `user` = %s", self.user)
		frappe.delete_doc("User", self.user, force=1, ignore_permissions=True, delete_permanently=True)
		frappe.db.commit()

	def _race(self, settings: dict, authorization: str | None = None) -> list:
		barrier = threading.Barrier(2)
		outcomes = queue.Queue()

		def register(seed: str):
			frappe.init(self.site, sites_path=self.sites_path)
			frappe.connect()
			try:
				doc = _credential_doc(self.user, seed)
				# Building the first DocType in a fresh test thread performs metadata
				# reads that are not part of a warm request worker. Start the raced
				# persistence transaction after that harness-only warmup.
				frappe.db.rollback()
				barrier.wait(timeout=10)
				registration._insert_verified_credential(
					doc,
					frappe._dict(settings),
					"explicit",
					authorization,
				)
				frappe.db.commit()
				outcomes.put(("success", doc.name))
			except frappe.AuthenticationError:
				frappe.db.rollback()
				outcomes.put(("reauth", None))
			except frappe.ValidationError:
				frappe.db.rollback()
				outcomes.put(("at_cap", None))
			except Exception as exc:
				frappe.db.rollback()
				outcomes.put(("error", f"{exc!r}\n{traceback.format_exc()}"))
			finally:
				frappe.destroy()

		threads = [threading.Thread(target=register, args=(seed,)) for seed in ("race-a", "race-b")]
		for thread in threads:
			thread.start()
		for thread in threads:
			thread.join(timeout=20)

		self.assertFalse(any(thread.is_alive() for thread in threads), "registration race deadlocked")
		results = [outcomes.get_nowait() for _thread in threads]
		return results

	def test_only_one_registration_succeeds_at_cap_one(self):
		results = self._race({"passkey_max_per_user": 1})
		self.assertEqual(sorted(result[0] for result in results), ["at_cap", "success"], results)
		self.assertEqual(frappe.db.count("WebAuthn Credential", {"user": self.user}), 1)
		self.assertEqual(frappe.db.count("WebAuthn User Handle", {"user": self.user}), 1)

	def test_only_one_weak_bootstrap_registration_succeeds(self):
		results = self._race(
			{
				"passkey_max_per_user": 10,
				"login_with_passkey": 1,
				"passkey_allow_first_enrollment_on_weak_login": 1,
			},
			authorization="weak",
		)
		self.assertEqual(sorted(result[0] for result in results), ["reauth", "success"], results)
		self.assertEqual(frappe.db.count("WebAuthn Credential", {"user": self.user}), 1)
