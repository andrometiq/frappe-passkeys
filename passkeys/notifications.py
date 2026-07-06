# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Out-of-band credential-change notifications (DESIGN-v1 §8.3) + risk-event
telemetry (§8.5) + admin-change owner notices (§8.6). Folds into
``frappe/passkey.py`` on the core merge.

**Hook-path import discipline (§1.3):** wired into the ``WebAuthn Credential``
``on_trash``/``validate`` DocType events and the login-ceremony flag path, so it
MUST NOT import ``webauthn``. It imports only ``frappe``.

The add/remove/flag email is the **compensating control for registration
hijack** (§8.3): it carries actionable metadata (label, time, IP) so a user who
did not initiate the change can react. It is gated on ``passkey_notify_on_change``
(off only for mail-less dev sites, §9.1). The password-fallback risk email is
gated on ``passkey_notify_password_fallback`` (default off, §8.5). Every
add/remove/flag also writes an Activity Log row. **Every sender is
exception-hardened**: a mail or logging failure must never break a ceremony, a
delete, or an admin save."""

import frappe
from frappe import _
from frappe.utils import cint, now_datetime

# Risk-event vocabulary (§8.5) — Activity-Log-backed telemetry for later signaling.
RISK_FALLBACK_USED = "fallback_used"
RISK_WEAK_LOGIN_ENROLLMENT = "weak_login_enrollment"
RISK_PASSWORD_LOGIN_BY_PASSKEY_HOLDER = "password_login_by_passkey_holder"


# ---------------------------------------------------------------------------
# credential-change notifications (§8.3 / §8.6)
# ---------------------------------------------------------------------------


def notify_credential_added(user: str, label: str, ip: str | None = None) -> None:
	""" "Passkey added" out-of-band email + Activity Log (§8.3). Called from the
	registration endpoint after a row is persisted."""
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
	""" "Passkey removed" out-of-band email + Activity Log (§8.3 / §8.6 — owner
	notification is sent even when a System Manager removes the row)."""
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
	""" "Passkey disabled" owner notice (§8.6): a System Manager soft-disabled a
	credential (disable > delete for forensics). Same compensating-control class as
	removal."""
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
	""" "Passkey flagged" out-of-band email + Activity Log (§8.3): a sign-count
	regression / anomaly was recorded on an assertion. Non-blocking telemetry that
	surfaces a possible clone."""
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


# ---------------------------------------------------------------------------
# risk events (§8.5) — Activity-Log-backed telemetry (+ one opt-in email)
# ---------------------------------------------------------------------------


def record_risk_event(event: str, user: str, detail: str | None = None) -> None:
	"""Log a §8.5 risk event to the Activity Log (telemetry for later signaling).
	The ``fallback_used`` event additionally emails when
	``passkey_notify_password_fallback`` is on (default off, §9.1). Non-blocking."""
	try:
		_activity_log(user, event, detail or event)
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
		frappe.log_error(title="passkeys: risk-event record failed")


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------


def _safe(user: str, *, activity: tuple, subject: str, body: str) -> None:
	"""Write the Activity Log row (always) + send the email (iff notify knob on).
	Fully exception-hardened."""
	try:
		_activity_log(user, activity[0], activity[1])
		if cint(frappe.db.get_single_value("Passkey Settings", "passkey_notify_on_change")):
			_send(user, subject, body)
	except Exception:
		frappe.log_error(title="passkeys: change-notification failed")


def _send(user: str, subject: str, message: str) -> None:
	email = frappe.db.get_value("User", user, "email") or user
	if not email or "@" not in email:
		return  # no deliverable address (system user) — Activity Log still recorded
	frappe.sendmail(recipients=[email], subject=subject, message=message, now=False)


def _activity_log(user: str, operation: str, subject: str) -> None:
	"""Best-effort Activity Log row (§8.3/§8.5). ``operation`` rides ``content`` (the
	Activity Log ``operation`` field is a closed Select in core); ``subject`` is the
	human line. Wrapped by the caller's try/except."""
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
	return _(" (from IP {0})").format(ip) if ip else ""
