# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Out-of-band credential-change notices, risk-event telemetry and the admin advisory.
Folds into ``frappe/passkey.py`` on the core merge. Called from DocType events, so it
must not import ``webauthn``.

The add/remove/flag email is the compensating control for registration hijack
(``passkey_notify_on_change``); every change also writes an Activity Log row. Every
sender is exception-hardened: a mail or log failure never breaks a ceremony, a delete
or an admin save."""

import frappe
from frappe import _
from frappe.utils import cint, get_datetime, now_datetime

from passkeys.install import DEFAULTS_PARENT

RISK_FALLBACK_USED = "fallback_used"
RISK_WEAK_LOGIN_ENROLLMENT = "weak_login_enrollment"
RISK_PASSWORD_LOGIN_BY_PASSKEY_HOLDER = "password_login_by_passkey_holder"
RISK_ENFORCE_INCAPABLE = "enforce_incapable_device"

# At most one incapable-device admin email per user per day; the client guard resets on
# every page load.
INCAPABLE_NOTIFY_WINDOW_SEC = 24 * 60 * 60


def notify_credential_added(user: str, label: str, ip: str | None = None) -> None:
	""" "Passkey added" email + Activity Log, after a registration is persisted."""
	_safe(
		user,
		activity=("passkey_added", _("Passkey added: {0}").format(label)),
		subject=_("A passkey was added to your account"),
		body=_(
			"A new passkey ({0}) was just added to your account on {1}.{2}"
			" If this wasn't you, remove it and change your password immediately."
		).format(label, _site_label(), _ip_suffix(ip)),
	)


def notify_credential_removed(user: str, label: str, ip: str | None = None) -> None:
	""" "Passkey removed" email + Activity Log, also when a System Manager removes it."""
	_safe(
		user,
		activity=("passkey_removed", _("Passkey removed: {0}").format(label)),
		subject=_("A passkey was removed from your account"),
		body=_(
			"A passkey ({0}) was removed from your account on {1}.{2}"
			" If this wasn't you, review your passkeys and sign-in methods."
		).format(label, _site_label(), _ip_suffix(ip)),
	)


def notify_credential_disabled(user: str, label: str) -> None:
	""" "Passkey disabled" notice: a System Manager soft-disabled the credential."""
	_safe(
		user,
		activity=("passkey_disabled", _("Passkey disabled: {0}").format(label)),
		subject=_("A passkey on your account was disabled"),
		body=_(
			"A passkey ({0}) on your account was disabled by an administrator on {1}."
			" You can no longer sign in with it. Contact your administrator if this was unexpected."
		).format(label, _site_label()),
	)


def notify_credential_flagged(user: str, label: str, reason: str | None = None) -> None:
	""" "Passkey flagged" email + Activity Log: a sign-count regression, a possible clone."""
	_safe(
		user,
		activity=("passkey_flagged", _("Passkey flagged: {0} ({1})").format(label, reason or "anomaly")),
		subject=_("A passkey on your account was flagged"),
		body=_(
			"A sign-in with your passkey ({0}) on {1} triggered a security check"
			" ({2}). This can indicate a cloned authenticator. If you did not"
			" recognize a recent sign-in, remove this passkey and review your account."
		).format(label, _site_label(), reason or _("anomaly")),
	)


def record_risk_event(event: str, user: str, detail: str | None = None) -> None:
	"""An Activity Log risk event; ``fallback_used`` also emails the user when
	``passkey_notify_password_fallback`` is on."""
	try:
		_activity_log(user, event, detail or event)
	except Exception:
		frappe.log_error(title="passkeys: risk-event audit failed")
	try:
		if event == RISK_FALLBACK_USED and cint(
			frappe.db.get_single_value("Passkey Settings", "passkey_notify_password_fallback")
		):
			_send(
				user,
				_("You signed in with a one-time code instead of your passkey"),
				_(
					"Your account has a passkey, but a recent sign-in on {0} used a one-time"
					" code (OTP) instead. If this wasn't you, review your account security."
				).format(_site_label()),
			)
	except Exception:
		frappe.log_error(title="passkeys: risk-event email failed")


def record_enforcement_incapable(user: str) -> None:
	"""Record an incapable-device report and email the System Managers, at most once per
	user per :data:`INCAPABLE_NOTIFY_WINDOW_SEC`."""
	try:
		_activity_log(
			user, RISK_ENFORCE_INCAPABLE, f"Passkey enforcement: {user}'s device cannot create a passkey"
		)
	except Exception:
		frappe.log_error(title="passkeys: enforcement-incapable audit failed")
	try:
		frappe.db.get_value("User", user, "name", for_update=True)
		if _incapable_notified_recently(user):
			return  # admins already advised within the window; the Activity Log still recorded
		managers = [m for m in _system_manager_emails() if m and m != user]
		if managers:
			frappe.sendmail(
				recipients=managers,
				subject=_("A user cannot satisfy passkey enrollment enforcement"),
				message=_(
					"{0} is required to register a passkey to keep signing in, but reports that"
					" their device cannot create one. Consider granting this user an exemption"
					" from the Passkeys section of their User form, resetting their grace budget,"
					" or issuing a hardware security key."
				).format(user),
				now=False,
			)
			_mark_incapable_notified(user)  # only after a dispatch — a manager-less site retries
	except Exception:
		frappe.log_error(title="passkeys: enforcement-incapable email failed")


def incapable_notify_key(user: str) -> str:
	return f"{user}_passkey_incapable_notified"


def _incapable_notified_recently(user: str) -> bool:
	raw = frappe.db.get_value(
		"DefaultValue",
		{"parent": DEFAULTS_PARENT, "defkey": incapable_notify_key(user)},
		"defvalue",
		for_update=True,
	)
	return bool(raw) and (now_datetime() - get_datetime(raw)).total_seconds() < INCAPABLE_NOTIFY_WINDOW_SEC


def _mark_incapable_notified(user: str) -> None:
	frappe.db.set_default(incapable_notify_key(user), now_datetime().isoformat(), parent=DEFAULTS_PARENT)


def _system_manager_emails() -> list[str]:
	"""Deliverable System Manager addresses (Administrator has no real inbox)."""
	from frappe.utils.user import get_system_managers

	return [m for m in get_system_managers(only_name=True) if m and "@" in m and m != "Administrator"]


def _safe(user: str, *, activity: tuple, subject: str, body: str) -> None:
	"""The Activity Log row, plus the email when ``passkey_notify_on_change`` is on; each
	independently exception-hardened."""
	try:
		_activity_log(user, activity[0], activity[1])
	except Exception:
		frappe.log_error(title="passkeys: change-notification audit failed")
	try:
		if cint(frappe.db.get_single_value("Passkey Settings", "passkey_notify_on_change")):
			_send(user, subject, body)
	except Exception:
		frappe.log_error(title="passkeys: change-notification email failed")


def _send(user: str, subject: str, message: str) -> None:
	email = frappe.db.get_value("User", user, "email") or user
	if not email or "@" not in email:
		return  # no deliverable address (system user) — Activity Log still recorded
	frappe.sendmail(recipients=[email], subject=subject, message=message, now=False)


def _activity_log(user: str, operation: str, subject: str) -> None:
	"""An Activity Log row; ``operation`` rides ``content`` because core's ``operation``
	field is a closed Select."""
	frappe.get_doc(
		{
			"doctype": "Activity Log",
			"subject": subject,
			"content": f"passkeys:{operation}",
			"user": user,
			"status": "Success",
			"communication_date": now_datetime(),
		}
	).insert(ignore_permissions=True)


def _site_label() -> str:
	return frappe.local.site or (frappe.db.get_single_value("Website Settings", "app_name") or "this site")


def _ip_suffix(ip: str | None) -> str:
	return " " + _("(from IP {0})").format(ip) if ip else ""
