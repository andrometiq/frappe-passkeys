# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""An impersonated session is read-only for the passkey DocTypes, proven through core's own
dispatch. The controllers (``ReadOnlyWhileImpersonated``) refuse every write verb with
``ImpersonatedSessionRefused``, whoever is impersonated: a System Manager, whose role grants
the write, and the Administrator, whom core's permission checks skip. Each request runs
``execute_cmd``; a refused request rolls back, as core's request handler does."""

import importlib
import json
from unittest.mock import patch

import frappe
from frappe.handler import execute_cmd
from frappe.utils import cint, set_request

from passkeys import session
from passkeys.errors import ImpersonatedSessionRefused
from passkeys.tests.compat import (
	IntegrationTestCase,
	arrange_clean_login_policy,
	arrange_mode_floor,
	flush_settings_cache,
)
from passkeys.tests.factories import make_credential, make_handle, make_user

CREDENTIAL = "WebAuthn Credential"
HANDLE = "WebAuthn User Handle"
SETTINGS = "Passkey Settings"
ROLE_ROW = "Passkey Enforcement Role"


def has_discard() -> bool:
	return hasattr(importlib.import_module("frappe.desk.form.save"), "discard")


class ImpersonationTestCase(IntegrationTestCase):
	def setUp(self):
		super().setUp()
		for attribute in ("request", "form_dict", "response"):
			self.addCleanup(setattr, frappe.local, attribute, getattr(frappe.local, attribute, None))
		self.addCleanup(frappe.set_user, "Administrator")
		self.addCleanup(flush_settings_cache)
		frappe.set_user("Administrator")
		arrange_mode_floor(self)
		arrange_clean_login_policy(self)
		self.owner = make_user()
		self.credential = make_credential(self.owner, label="Laptop")
		make_credential(self.owner, label="Phone")  # survives a delete, past the last-passkey guard
		self.handle = make_handle(self.owner)

	def make_system_manager(self) -> str:
		user = make_user()
		frappe.get_doc("User", user).add_roles("System Manager")
		return user

	def make_role_row(self):
		"""A Passkey Settings enforcement-role row, written without the Settings save."""
		row = frappe.get_doc(
			{
				"doctype": ROLE_ROW,
				"parenttype": SETTINGS,
				"parent": SETTINGS,
				"parentfield": "passkey_enforce_roles",
				"role": "System Manager",
				"idx": 99,
			}
		)
		row.db_insert()
		return row

	def act_as(self, user: str, *, impersonated: bool) -> None:
		frappe.set_user(user)
		if impersonated:
			frappe.session.data.impersonated_by = "Administrator"

	def dispatch(self, cmd: str, *, http_method: str = "POST", **form):
		set_request(method=http_method, path=f"/api/method/{cmd}")
		frappe.local.form_dict = frappe._dict(form)
		frappe.local.response = frappe._dict(docs=[])
		frappe.db.savepoint("impersonation_request")
		try:
			return execute_cmd(cmd)
		except Exception:
			frappe.db.rollback(save_point="impersonation_request")
			raise

	def doc_json(self, doctype: str, name: str, **changes) -> str:
		return frappe.as_json({**frappe.get_doc(doctype, name).as_dict(), **changes})


class TestSystemManager(ImpersonationTestCase):
	"""The role grants these writes, so each refusal is the controller's, and the same
	request goes through once the session is not impersonated."""

	def test_no_session_is_not_impersonated(self):
		"""The controllers also run in the scheduler, CLI and migrate."""
		self.addCleanup(setattr, frappe.local, "session", frappe.local.session)
		frappe.local.session = None
		self.assertFalse(session.is_impersonated())
		frappe.local.session = frappe._dict()
		self.assertFalse(session.is_impersonated())

	def test_reads_stay_open(self):
		self.act_as(self.make_system_manager(), impersonated=True)
		for doctype, name in (
			(CREDENTIAL, self.credential.name),
			(HANDLE, self.handle.name),
			(SETTINGS, SETTINGS),
		):
			with self.subTest(doctype=doctype):
				self.dispatch("frappe.desk.form.load.getdoc", http_method="GET", doctype=doctype, name=name)
				self.assertEqual(frappe.local.response.docs[0].name, name)
				self.assertEqual(
					self.dispatch("frappe.client.get", http_method="GET", doctype=doctype, name=name)["name"],
					name,
				)

	def assertOnlyImpersonationRefuses(self, cmd: str, form, is_unchanged) -> None:
		"""``form`` is called per request."""
		manager = self.make_system_manager()
		self.act_as(manager, impersonated=True)
		with self.assertRaises(ImpersonatedSessionRefused):
			self.dispatch(cmd, **form())
		frappe.set_user("Administrator")
		self.assertTrue(is_unchanged(), cmd)

		self.act_as(manager, impersonated=False)
		self.dispatch(cmd, **form())
		frappe.set_user("Administrator")
		self.assertFalse(is_unchanged(), cmd)

	def label_unchanged(self) -> bool:
		return frappe.db.get_value(CREDENTIAL, self.credential.name, "label") == "Laptop"

	def test_client_save_is_refused(self):
		self.assertOnlyImpersonationRefuses(
			"frappe.client.save",
			lambda: {"doc": self.doc_json(CREDENTIAL, self.credential.name, label="Renamed")},
			self.label_unchanged,
		)

	def test_form_save_is_refused(self):
		self.assertOnlyImpersonationRefuses(
			"frappe.desk.form.save.savedocs",
			lambda: {
				"doc": self.doc_json(CREDENTIAL, self.credential.name, label="Renamed"),
				"action": "Save",
			},
			self.label_unchanged,
		)

	def test_client_set_value_is_refused(self):
		self.assertOnlyImpersonationRefuses(
			"frappe.client.set_value",
			lambda: {
				"doctype": HANDLE,
				"name": self.handle.name,
				"fieldname": "passkey_only_login",
				"value": 1,
			},
			lambda: not frappe.db.get_value(HANDLE, self.handle.name, "passkey_only_login"),
		)

	def test_client_delete_is_refused(self):
		self.assertOnlyImpersonationRefuses(
			"frappe.client.delete",
			lambda: {"doctype": CREDENTIAL, "name": self.credential.name},
			lambda: bool(frappe.db.exists(CREDENTIAL, self.credential.name)),
		)

	def test_discard_is_refused(self):
		if not has_discard():
			self.skipTest("Document.discard is v16+")
		self.assertOnlyImpersonationRefuses(
			"frappe.desk.form.save.discard",
			lambda: {"doctype": CREDENTIAL, "name": self.credential.name},
			lambda: frappe.db.get_value(CREDENTIAL, self.credential.name, "docstatus") == 0,
		)


class TestAdministrator(ImpersonationTestCase):
	"""Target: the Administrator, whom core's permission checks skip, so only the
	controllers stand."""

	def assertGuardRefuses(self, cmd: str, **form) -> None:
		self.act_as("Administrator", impersonated=True)
		with self.assertRaises(ImpersonatedSessionRefused):
			self.dispatch(cmd, **form)
		frappe.set_user("Administrator")

	def settings_state(self) -> tuple:
		"""Every Passkey Settings row in tabSingles (a discard would write docstatus there) and
		every enforcement-role row."""
		return (
			frappe.db.sql(
				"SELECT `field`, `value` FROM `tabSingles` WHERE `doctype` = %s ORDER BY `field`", (SETTINGS,)
			),
			frappe.db.sql(
				"SELECT `name`, `role` FROM `tabPasskey Enforcement Role` WHERE `parent` = %s ORDER BY `name`",
				(SETTINGS,),
			),
		)

	def test_mixin_is_on_every_passkey_controller(self):
		for doctype in (CREDENTIAL, HANDLE, SETTINGS, ROLE_ROW):
			with self.subTest(doctype=doctype):
				controller = frappe.get_doc({"doctype": doctype})
				self.assertIsInstance(controller, session.ReadOnlyWhileImpersonated)
				self.act_as("Administrator", impersonated=True)
				for verb, args in (
					("validate", ()),
					("on_trash", ()),
					("before_rename", ("a", "b")),
					("after_rename", ("a", "b")),
					("before_discard", ()),
				):
					with self.subTest(verb=verb), self.assertRaises(ImpersonatedSessionRefused):
						getattr(controller, verb)(*args)
				frappe.set_user("Administrator")

	def test_saves_are_refused(self):
		row = self.make_role_row()
		before = self.settings_state()
		window = cint(frappe.db.get_single_value(SETTINGS, "passkey_reauth_window", cache=False))
		writes = {
			"credential save": (
				"frappe.client.save",
				{"doc": self.doc_json(CREDENTIAL, self.credential.name, label="Renamed")},
			),
			"handle set_value": (
				"frappe.client.set_value",
				{"doctype": HANDLE, "name": self.handle.name, "fieldname": "passkey_only_login", "value": 1},
			),
			"settings set_value": (
				"frappe.client.set_value",
				{
					"doctype": SETTINGS,
					"name": SETTINGS,
					"fieldname": "passkey_reauth_window",
					"value": window + 60,
				},
			),
			"credential insert": (
				"frappe.client.insert",
				{"doc": frappe.as_json({"doctype": CREDENTIAL, "user": self.owner, "label": "Forged"})},
			),
			"role row insert": (
				"frappe.client.insert",
				{
					"doc": frappe.as_json(
						{
							"doctype": ROLE_ROW,
							"parenttype": SETTINGS,
							"parent": SETTINGS,
							"parentfield": "passkey_enforce_roles",
							"role": "Guest",
						}
					)
				},
			),
			"role row save": ("frappe.client.save", {"doc": self.doc_json(ROLE_ROW, row.name, role="Guest")}),
		}
		for write, (cmd, form) in writes.items():
			with self.subTest(write=write):
				self.assertGuardRefuses(cmd, **form)
		self.assertEqual(frappe.db.get_value(CREDENTIAL, self.credential.name, "label"), "Laptop")
		self.assertFalse(frappe.db.get_value(HANDLE, self.handle.name, "passkey_only_login"))
		self.assertEqual(self.settings_state(), before)
		self.assertEqual(frappe.db.count(CREDENTIAL, {"user": self.owner}), 2)

	def test_deletes_are_refused(self):
		"""The Single delete removes its tabSingles rows and every role row by SQL after
		on_trash, and the role rows' own on_trash never runs."""
		row = self.make_role_row()
		before = self.settings_state()
		for doctype, name in (
			(CREDENTIAL, self.credential.name),
			(HANDLE, self.handle.name),
			(SETTINGS, SETTINGS),
			(ROLE_ROW, row.name),
		):
			with self.subTest(doctype=doctype):
				self.assertGuardRefuses("frappe.client.delete", doctype=doctype, name=name)
		self.assertTrue(frappe.db.exists(CREDENTIAL, self.credential.name))
		self.assertTrue(frappe.db.exists(HANDLE, self.handle.name))
		self.assertTrue(frappe.db.exists(ROLE_ROW, row.name))
		self.assertEqual(self.settings_state(), before)

	def test_renames_are_refused_even_without_validation(self):
		"""``Document.rename`` is whitelisted with ``validate_rename``; ``false`` skips the
		permission check and before_rename, so after_rename is the only hook left."""
		row = self.make_role_row()
		cmd = "frappe.handler.run_doc_method"

		def rename_args(new: str, validate: bool) -> str:
			return json.dumps({"name": new, "validate_rename": validate})

		with patch("frappe.enqueue"):  # rename queues a global-search rebuild
			for validate in (False, True):
				for doctype, name in (
					(CREDENTIAL, self.credential.name),
					(HANDLE, self.handle.name),
					(ROLE_ROW, row.name),
				):
					with self.subTest(doctype=doctype, validate_rename=validate):
						self.assertGuardRefuses(
							cmd,
							method="rename",
							dt=doctype,
							dn=name,
							args=rename_args(f"{name}-renamed", validate),
						)
						self.assertTrue(frappe.db.exists(doctype, name))
			with self.subTest(form="docs"):
				self.assertGuardRefuses(
					cmd,
					method="rename",
					docs=self.doc_json(CREDENTIAL, self.credential.name),
					args=rename_args("renamed-from-json", False),
				)
				self.assertTrue(frappe.db.exists(CREDENTIAL, self.credential.name))

			# Without impersonation core renames it: the refusals above closed a real path.
			new_name = frappe.generate_hash()
			self.dispatch(
				cmd,
				method="rename",
				dt=CREDENTIAL,
				dn=self.credential.name,
				args=rename_args(new_name, False),
			)
		self.assertFalse(frappe.db.exists(CREDENTIAL, self.credential.name))
		self.assertTrue(frappe.db.exists(CREDENTIAL, new_name))

	def test_discards_are_refused(self):
		if not has_discard():
			self.skipTest("Document.discard is v16+")
		before = self.settings_state()
		for doctype, name in (
			(CREDENTIAL, self.credential.name),
			(HANDLE, self.handle.name),
			(SETTINGS, SETTINGS),
		):
			with self.subTest(doctype=doctype):
				self.assertGuardRefuses("frappe.desk.form.save.discard", doctype=doctype, name=name)
		self.assertEqual(frappe.db.get_value(CREDENTIAL, self.credential.name, "docstatus"), 0)
		self.assertEqual(frappe.db.get_value(HANDLE, self.handle.name, "docstatus"), 0)
		self.assertEqual(self.settings_state(), before)
