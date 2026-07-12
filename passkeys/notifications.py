# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Out-of-band credential-change notifications + risk-event
telemetry + admin-change owner notices. Folds into
``frappe/passkey.py`` on the core merge.

**Hook-path import discipline:** wired into the ``WebAuthn Credential``
``on_trash``/``validate`` DocType events and the login-ceremony flag path, so it
MUST NOT import ``webauthn``. It imports only ``frappe`` and the webauthn-free
``passkeys.install`` (for the shared ``__passkeys`` Defaults parent).

The add/remove/flag email is the **compensating control for registration
hijack**: it carries actionable metadata (label, time, IP) so a user who
did not initiate the change can react. It is gated on ``passkey_notify_on_change``
(off only for mail-less dev sites). The password-fallback risk email is
gated on ``passkey_notify_password_fallback`` (default off). Every
add/remove/flag also writes an Activity Log row. **Every sender is
exception-hardened**: a mail or logging failure must never break a ceremony, a
delete, or an admin save."""

import frappe
from frappe import _
from frappe.utils import cint, get_datetime, now_datetime

from passkeys.install import DEFAULTS_PARENT

# Risk-event vocabulary — Activity-Log-backed telemetry for later signaling.
RISK_FALLBACK_USED = "fallback_used"
RISK_WEAK_LOGIN_ENROLLMENT = "weak_login_enrollment"
RISK_PASSWORD_LOGIN_BY_PASSKEY_HOLDER = "password_login_by_passkey_holder"
RISK_ENFORCE_INCAPABLE = "enforce_incapable_device"

# Admin-advisory dedup window: at most one incapable-device email per user per 24h.
# The client once-guard resets on every page load, so without a server-side gate one
# in-scope incapable user could email every System Manager once per page view (up to
# the endpoint's 30/hr rate cap). The window marker is stored the twofactor way — a
# site-wide ``DefaultValue`` under ``__passkeys``, exactly like the grace state — so it
# is shared across the user's browsers and swept on uninstall. The endpoint rate limit
# stays as the coarse backstop.
INCAPABLE_NOTIFY_WINDOW_SEC = 24 * 60 * 60


# ---------------------------------------------------------------------------
# credential-change notifications
# ---------------------------------------------------------------------------


def notify_credential_added(user: str, label: str, ip: str | None = None) -> None:
	""" "Passkey added" out-of-band email + Activity Log. Called from the
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
	""" "Passkey removed" out-of-band email + Activity Log (owner
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
	""" "Passkey disabled" owner notice: a System Manager soft-disabled a
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
	""" "Passkey flagged" out-of-band email + Activity Log: a sign-count
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
# risk events — Activity-Log-backed telemetry (+ one opt-in email)
# ---------------------------------------------------------------------------


def record_risk_event(event: str, user: str, detail: str | None = None) -> None:
	"""Log a risk event to the Activity Log (telemetry for later signaling).
	The ``fallback_used`` event additionally emails when
	``passkey_notify_password_fallback`` is on (default off). Non-blocking."""
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


def record_enforcement_incapable(user: str) -> None:
	"""The ``Block + Notify Admin`` half of the incapable-device escape hatch: a user in
	scope for passkey enrollment enforcement reported their device cannot create a
	passkey. Record an Activity Log risk event (**always** — telemetry) and best-effort
	email the System Managers so they can grant an exemption or issue a security key. The
	admin email is **deduped server-side** to at most one per user per 24h
	(:data:`INCAPABLE_NOTIFY_WINDOW_SEC`): the client once-guard resets each page load, so
	the dedup is what stops a single incapable user flooding admins one email per page view.
	Non-blocking — a mail/log failure must never break the interstitial."""
	try:
		_activity_log(
			user, RISK_ENFORCE_INCAPABLE, f"Passkey enforcement: {user}'s device cannot create a passkey"
		)
		if _incapable_notified_recently(user):
			return  # admins already advised within the window; the Activity Log still recorded
		managers = [m for m in _system_manager_emails() if m and m != user]
		if managers:
			frappe.sendmail(
				recipients=managers,
				subject=_("A user cannot satisfy passkey enrollment enforcement"),
				message=_(
					"{0} is required to register a passkey to keep signing in, but reports that"
					" their device cannot create one. Consider granting an exemption (add one of"
					" their roles to the exempt list) or issuing a hardware security key."
				).format(user),
				now=False,
			)
			_mark_incapable_notified(user)  # only after a dispatch — a manager-less site retries
	except Exception:
		frappe.log_error(title="passkeys: enforcement-incapable advisory failed")


def _incapable_notify_key(user: str) -> str:
	return f"{user}_passkey_incapable_notified"


def _incapable_notified_recently(user: str) -> bool:
	"""True iff an incapable-device admin advisory was emailed for ``user`` within the
	dedup window. Absent/malformed marker ⇒ False (fail open to sending — a bad row must
	never permanently silence the advisory)."""
	raw = frappe.db.get_default(_incapable_notify_key(user), parent=DEFAULTS_PARENT)
	if not raw:
		return False
	try:
		last = get_datetime(raw)
	except Exception:
		return False
	return (now_datetime() - last).total_seconds() < INCAPABLE_NOTIFY_WINDOW_SEC


def _mark_incapable_notified(user: str) -> None:
	"""Stamp the dedup window marker (twofactor-style ``DefaultValue`` under
	``__passkeys``, swept on uninstall) after an advisory is dispatched."""
	frappe.db.set_default(_incapable_notify_key(user), now_datetime().isoformat(), parent=DEFAULTS_PARENT)


def _system_manager_emails() -> list[str]:
	"""Deliverable System-Manager addresses (excludes Administrator, which has no real
	inbox on most sites). Best-effort — returns [] on any error."""
	try:
		from frappe.utils.user import get_system_managers

		return [m for m in get_system_managers() if m and "@" in m and m != "Administrator"]
	except Exception:
		return []


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
	"""Best-effort Activity Log row. ``operation`` rides ``content`` (the
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
