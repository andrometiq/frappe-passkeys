# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Admin security-posture verdict for the Passkey Settings page (folds into
``frappe/passkey.py`` on the core merge): given everything else this site allows, can a
user meant to use a passkey still sign in without one?

:func:`classify_posture` is pure (no DB, no request); :func:`build_posture` does the
reads. The surface is System-Manager-only, so the copy names the exact setting to change."""

import frappe
from frappe import _
from frappe.utils import cint

# The client renderer (``posturePanel``) mirrors this order.
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}

# A re-auth window (seconds) above this gets a low-severity row.
_REAUTH_WINDOW_NOTICE_THRESHOLD = 900


def _row(code, severity, what, why, recommendation, detectable=True, bypass_label=None):
	return {
		"code": code,
		"severity": severity,
		"what": what,
		"why": why,
		"recommendation": recommendation,
		"detectable": detectable,
		"bypass_label": bypass_label,
	}


def classify_posture(ctx: dict) -> dict:
	"""``{"verdict": {...}, "rows": [...]}`` from primitive auth facts. A row carrying a
	``bypass_label`` is an active bypass and feeds the verdict headline.

	In first-factor mode a passkey is *a* first factor, so every other one (password,
	email link, social, LDAP) is a bypass. With the second factor on, enrolled users are
	vetoed on every stock login path until they complete the passkey (or OTP-fallback)
	leg, so alternate methods only constrain availability."""
	first = bool(ctx.get("first_factor"))
	second = bool(ctx.get("second_factor"))
	otp_fallback = bool(ctx.get("otp_fallback_enabled"))
	config_read_failed = bool(ctx.get("config_read_failed"))
	pw_enabled = bool(ctx.get("password_login_enabled"))
	email_link = bool(ctx.get("email_link_login"))
	providers = list(ctx.get("social_providers") or [])
	ldap = bool(ctx.get("ldap_enabled"))
	core_2fa = bool(ctx.get("core_2fa_enabled"))
	core_2fa_method = ctx.get("core_2fa_method")
	passkey_only_count = cint(ctx.get("passkey_only_user_count"))
	login_user_count = cint(ctx.get("login_user_count"))
	enforcement = ctx.get("enforcement_effective") or "off"
	hard_fail = bool(ctx.get("sign_count_hard_fail"))
	reauth_window = cint(ctx.get("reauth_window"))

	rows = []
	pw_is_bypass = first and pw_enabled and not second
	alternate_is_bypass = first and not second
	if config_read_failed:
		rows.append(_degraded_row())

	if not (first or second):
		rows.append(
			_row(
				"no_mode",
				"info",
				_("Passkeys are not an active login factor."),
				_("No passkey login mode is on, so every sign-in uses another method."),
				_("Turn on 'Login with Passkey' or 'Passkey as Second Factor' above to start."),
			)
		)
		rows.append(_custom_apps_row())
		if config_read_failed:
			return {"verdict": _undetermined_verdict(), "rows": rows}
		return {
			"verdict": _verdict(_("Passkeys are not an active login factor on this site."), "info"),
			"rows": rows,
		}

	if pw_is_bypass:
		rows.append(
			_row(
				"password_login",
				"high",
				_("Password sign-in is enabled."),
				_("Any user can sign in with a username and password instead of a passkey."),
				_(
					"Turn on 'Disable Username/Password Login' in System Settings to remove it "
					"site-wide, or set 'Passwordless login only' per user (needs 2+ passkeys)."
				),
				bypass_label=_("password sign-in"),
			)
		)

	if second and otp_fallback:
		rows.append(
			_row(
				"otp_fallback",
				"high",
				_("OTP fallback is enabled for passkey second factor."),
				_(
					"An enrolled user can finish password sign-in with a verification code instead of a passkey."
				),
				_("Turn off 'Allow OTP Fallback' to require the passkey leg for enrolled users."),
				bypass_label=_("OTP fallback"),
			)
		)

	if providers and alternate_is_bypass:
		rows.append(
			_row(
				"social_login",
				"high",
				_("Social login is enabled: {0}.").format(", ".join(providers)),
				_("A user can sign in through these identity providers without a passkey."),
				_("Disable these Social Login Keys, or accept that these providers can bypass passkeys."),
				bypass_label=_("social login"),
			)
		)
	elif providers:
		rows.append(
			_row(
				"social_login",
				"medium",
				_("Social login is enabled: {0}.").format(", ".join(providers)),
				_("Enrolled users cannot finish these login paths without this app's passkey leg."),
				_(
					"Keep 'Login with Passkey' on for enrolled accounts that rely on social login, "
					"or ensure they can start the app's password-to-passkey flow."
				),
			)
		)

	if ldap and alternate_is_bypass:
		rows.append(
			_row(
				"ldap",
				"high",
				_("LDAP sign-in is enabled."),
				_("A user can sign in with their LDAP / Active Directory password instead of a passkey."),
				_("Disable LDAP in LDAP Settings, or accept that LDAP logins can bypass passkeys."),
				bypass_label=_("LDAP sign-in"),
			)
		)
	elif ldap:
		rows.append(
			_row(
				"ldap",
				"medium",
				_("LDAP sign-in is enabled."),
				_("Enrolled users cannot finish LDAP login without this app's passkey leg."),
				_(
					"Keep 'Login with Passkey' on for enrolled LDAP-only accounts, or ensure they "
					"can start the app's password-to-passkey flow."
				),
			)
		)

	# core 2FA is the required defence-in-depth floor behind the final login veto
	if second:
		if not core_2fa:
			rows.append(
				_row(
					"core_2fa_off",
					"high",
					_("Two Factor Authentication is off."),
					_(
						"Passkey as Second Factor requires core Two Factor Authentication as a "
						"defence-in-depth floor. The final login veto still blocks enrolled users, "
						"but this configuration is unsupported."
					),
					_("Enable 'Two Factor Authentication' in System Settings."),
				)
			)
		else:
			method = core_2fa_method or _("a verification code")
			rows.append(
				_row(
					"core_2fa_on",
					"info",
					_("Two Factor Authentication is on ({0}).").format(method),
					_("This is the required core floor behind the app's final-login veto."),
					_("No change needed — this is the intended second-factor floor."),
				)
			)

	if email_link and alternate_is_bypass:
		rows.append(
			_row(
				"email_link",
				"medium",
				_("Login with email link is enabled."),
				_("A user can sign in through an emailed link without a passkey."),
				_("Turn off 'Login with Email Link' in System Settings."),
				bypass_label=_("email-link sign-in"),
			)
		)
	elif email_link:
		rows.append(
			_row(
				"email_link",
				"medium",
				_("Login with email link is enabled."),
				_("Enrolled users cannot finish email-link login without this app's passkey leg."),
				_(
					"Keep 'Login with Passkey' on for enrolled email-link-only accounts, or ensure "
					"they can start the app's password-to-passkey flow."
				),
			)
		)

	# password reset by email amplifies the password bypass
	if pw_is_bypass:
		rows.append(
			_row(
				"password_reset",
				"medium",
				_("Password reset by email is available."),
				_(
					"Anyone who controls a user's email can reset the password and then sign in "
					"without a passkey."
				),
				_("This is inherent to password sign-in — disable password sign-in to remove it."),
			)
		)

		if login_user_count > 0:
			rows.append(
				_row(
					"adoption",
					"info",
					_("{0} of {1} users use passwordless-only login.").format(
						passkey_only_count, login_user_count
					),
					_("Everyone else can still fall back to a password, so passkeys are optional for them."),
					_enforcement_recommendation(enforcement),
				)
			)

	# app hardening rows (not bypasses)
	if not hard_fail:
		rows.append(
			_row(
				"sign_count_soft",
				"low",
				_("Cloned-authenticator hard-fail is off."),
				_(
					"A sign-count regression (a possible cloned passkey) is flagged and the owner "
					"notified, but the sign-in still succeeds."
				),
				_(
					"Turn on 'Reject on sign-count regression' to hard-fail a suspected clone "
					"(may lock out authenticators with buggy counters)."
				),
			)
		)

	if reauth_window > _REAUTH_WINDOW_NOTICE_THRESHOLD:
		rows.append(
			_row(
				"reauth_window",
				"low",
				_("Re-auth window is {0} seconds.").format(reauth_window),
				_("Passkey management stays authorized for this long after a sign-in or re-auth."),
				_("Lower 'Re-auth Window (seconds)' if management should re-verify sooner."),
			)
		)

	rows.append(_custom_apps_row())  # the honest limit, not deterministically detectable

	ordered = sorted(rows, key=lambda r: SEVERITY_RANK.get(r["severity"], 9))
	bypass_labels = [r["bypass_label"] for r in ordered if r.get("bypass_label")]
	if bypass_labels:
		verdict = _verdict(
			_("Users can still sign in without a passkey via: {0}.").format(", ".join(bypass_labels)),
			"high",
			bypass_labels,
			config_read_failed,
		)
	elif config_read_failed:
		verdict = _undetermined_verdict()
	else:
		verdict = _verdict(
			_("No stock bypass paths detected — passkeys are the only stock way to sign in."), "good"
		)
	return {"verdict": verdict, "rows": rows}


def _verdict(headline: str, tone: str, bypass_labels: list | None = None, degraded: bool = False) -> dict:
	return {
		"headline": headline,
		"tone": tone,
		"can_bypass": bool(bypass_labels),
		"bypass_labels": bypass_labels or [],
		"degraded": degraded,
	}


def _undetermined_verdict() -> dict:
	return _verdict(_("Security posture could not be fully determined."), "high", degraded=True)


def _enforcement_recommendation(enforcement: str) -> str:
	if enforcement == "enforce":
		return _(
			"Enrollment is enforcing — once users enroll, set 'Passwordless login only' for the "
			"users you want to fully cover."
		)
	return _(
		"Raise adoption with an Enrollment Policy, then set 'Passwordless login only' for covered users."
	)


def _custom_apps_row() -> dict:
	return _row(
		"custom_apps",
		"info",
		_("Custom apps may add their own login methods."),
		_(
			"A custom app can register its own auth hooks or login endpoints, which cannot be "
			"detected deterministically."
		),
		_("Review any custom login code separately — this checklist covers stock Frappe only."),
		detectable=False,
	)


def _degraded_row() -> dict:
	return _row(
		"posture_degraded",
		"high",
		_("Security posture could not be fully determined."),
		_("One or more stock authentication settings could not be read."),
		_("Retry the check and inspect the failed System Settings, Social Login, or LDAP configuration."),
	)


def build_posture() -> dict:
	"""Read the site's auth surface and classify it; a failed read marks the verdict
	degraded instead of guessing."""
	from passkeys import boot

	settings = frappe.get_cached_doc("Passkey Settings")
	failed_reads = []

	def read(fetch, default=None):
		try:
			return fetch()
		except Exception:
			failed_reads.append(fetch)
			return default

	core_2fa = bool(cint(read(lambda: _system_setting("enable_two_factor_auth"))))
	facts = {
		"password_login_enabled": not cint(read(lambda: _system_setting("disable_user_pass_login"))),
		"email_link_login": bool(cint(read(lambda: _system_setting("login_with_email_link")))),
		"social_providers": read(_enabled_social_providers, []),
		"ldap_enabled": read(_ldap_enabled, False),
		"core_2fa_enabled": core_2fa,
		"core_2fa_method": read(lambda: _system_setting("two_factor_method")) if core_2fa else None,
	}
	passkey_only_count, login_user_count = _adoption_counts()
	return classify_posture(
		{
			**facts,
			"config_read_failed": bool(failed_reads),
			"first_factor": bool(cint(settings.login_with_passkey)),
			"second_factor": bool(cint(settings.passkey_as_second_factor)),
			"otp_fallback_enabled": bool(cint(settings.passkey_2fa_allow_otp_fallback)),
			"passkey_only_user_count": passkey_only_count,
			"login_user_count": login_user_count,
			"enforcement_effective": boot.policy_effective(settings),
			"sign_count_hard_fail": bool(cint(settings.passkey_sign_count_hard_fail)),
			"reauth_window": cint(settings.passkey_reauth_window),
		}
	)


def _adoption_counts() -> tuple[int, int]:
	"""``(passkey_only_count, login_user_count)`` over the same population — enabled users
	other than Administrator and Guest — so the numerator never exceeds the denominator."""
	from frappe.query_builder.functions import Count

	User = frappe.qb.DocType("User")
	Handle = frappe.qb.DocType("WebAuthn User Handle")
	eligible = (User.enabled == 1) & (User.name.notin(["Administrator", "Guest"]))

	login_user_count = frappe.qb.from_(User).select(Count("*")).where(eligible).run()[0][0]
	passkey_only_count = (
		frappe.qb.from_(Handle)
		.inner_join(User)
		.on(Handle.user == User.name)
		.select(Count("*"))
		.where(Handle.passkey_only_login == 1)
		.where(eligible)
		.run()[0][0]
	)
	return cint(passkey_only_count), cint(login_user_count)


def _system_setting(field: str):
	return frappe.db.get_single_value("System Settings", field)


def _enabled_social_providers() -> list:
	"""Display labels of the enabled Social Login Keys."""
	rows = frappe.get_all(
		"Social Login Key",
		filters={"enable_social_login": 1},
		fields=["name", "provider_name", "social_login_provider"],
	)
	return [str(row.provider_name or row.social_login_provider or row.name) for row in rows]


def _ldap_enabled() -> bool:
	if not frappe.db.exists("DocType", "LDAP Settings"):
		return False
	return bool(cint(frappe.db.get_single_value("LDAP Settings", "enabled")))
