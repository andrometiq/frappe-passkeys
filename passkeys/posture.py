# Copyright (c) 2026, Frappe Passkeys Contributors
# License: MIT. See LICENSE

"""Admin security-posture verdict for the Passkey Settings page (folds into
``frappe/passkey.py`` on the core merge).

The owner-facing question this answers: *given everything else this site allows —
password login, email-link login, social/LDAP sign-in, the core second factor — can a
user who is meant to use a passkey still get in without one?* :func:`classify_posture`
is a **pure** function (no DB, no request) that takes the site's already-read auth
facts and returns a structured verdict + severity-ordered rows; :func:`build_posture`
does the actual config reads and calls it. The whitelisted, System-Manager-gated
endpoint that surfaces this lives next to its sibling read endpoint in
``passkey_settings.py`` (``get_security_posture``).

Copy is deliberately concrete (names the exact setting to change): this surface is
System-Manager-only, so — unlike the guest login copy — revealing the mechanic is the
right call (the reveal-vs-vague split in the error-copy playbook)."""

import frappe
from frappe import _
from frappe.utils import cint

# Severity ranks. The client renderer (``passkey_manage_common.bundle.js::posturePanel``)
# mirrors this order; the detectability disclaimer always sorts last regardless.
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}

# The re-auth window (seconds) above which we surface it as a low-severity heads-up.
# Below this the default is unremarkable and we stay quiet (no wall of rows).
_REAUTH_WINDOW_NOTICE_THRESHOLD = 900


def _row(code, severity, what, why, recommendation, detectable=True, bypass_label=None):
	return {
		"code": code,
		"severity": severity,
		"what": what,
		"why": why,
		"recommendation": recommendation,
		"detectable": detectable,
		# Present ⇒ this row is an active bypass path; feeds the top verdict line.
		"bypass_label": bypass_label,
	}


def classify_posture(ctx: dict) -> dict:
	"""Pure verdict builder. ``ctx`` carries only primitives (no DB / request), so this
	is unit-testable across every permutation. Returns
	``{"verdict": {...}, "rows": [...]}`` where each row is
	``{code, severity, what, why, recommendation, detectable, bypass_label}``.

	Mode lens:
	  * **first-factor** (``login_with_passkey``): a passkey is *a* first factor, so
	    every OTHER first factor (password / email-link / social / LDAP) is a bypass.
	  * **second-factor only** (``passkey_as_second_factor`` without first-factor):
	    a password login is funnelled through the passkey step, so it is NOT itself a
	    bypass — the bypasses are the paths that skip the passkey step (social / email
	    link) and, critically, core Two Factor Authentication being off (the floor)."""
	first = bool(ctx.get("first_factor"))
	second = bool(ctx.get("second_factor"))
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
	any_mode = first or second
	# In first-factor mode, password login is an alternative first factor. In
	# second-factor-only mode it rides the passkey step, so it is not a bypass.
	pw_is_bypass = first and pw_enabled

	# ---- no active passkey mode -------------------------------------------------
	if not any_mode:
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
		return {
			"verdict": {
				"headline": _("Passkeys are not an active login factor on this site."),
				"tone": "info",
				"can_bypass": False,
				"bypass_labels": [],
			},
			"rows": rows,
		}

	# ---- first-factor bypass paths ---------------------------------------------
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

	if providers:
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

	if ldap:
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

	# Core 2FA is only a passkey factor in second-factor mode (its floor). Off ⇒ a
	# direct password sign-in that skips the passkey step has no second factor at all.
	if second:
		if not core_2fa:
			rows.append(
				_row(
					"core_2fa_off",
					"high",
					_("Two Factor Authentication is off."),
					_(
						"Passkey as Second Factor relies on core Two Factor Authentication as its "
						"floor; with it off, a password sign-in that does not use the passkey step "
						"has no second factor."
					),
					_("Enable 'Two Factor Authentication' in System Settings."),
					bypass_label=_("password sign-ins with no second factor"),
				)
			)
		else:
			method = core_2fa_method or _("a verification code")
			rows.append(
				_row(
					"core_2fa_on",
					"info",
					_("Two Factor Authentication is on ({0}).").format(method),
					_("Sign-ins that skip the passkey step fall back to this second factor."),
					_("No change needed — this is the intended second-factor floor."),
				)
			)

	# Email-link login skips the passkey step in either mode.
	if email_link:
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

	# Password reset by email amplifies the password bypass (only meaningful while
	# password sign-in itself is a bypass path).
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

		# Adoption context: how many users are actually locked to passwordless-only.
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

	# ---- app hardening rows (not bypasses) -------------------------------------
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

	# ---- honest limit (always last, not deterministically detectable) ----------
	rows.append(_custom_apps_row())

	# ---- top verdict from the emitted bypass rows ------------------------------
	ordered = sorted(rows, key=lambda r: SEVERITY_RANK.get(r["severity"], 9))
	bypass_labels = [r["bypass_label"] for r in ordered if r.get("bypass_label")]
	if bypass_labels:
		verdict = {
			"headline": _("Users can still sign in without a passkey via: {0}.").format(
				", ".join(bypass_labels)
			),
			"tone": "high",
			"can_bypass": True,
			"bypass_labels": bypass_labels,
		}
	else:
		verdict = {
			"headline": _("No stock bypass paths detected — passkeys are the only stock way to sign in."),
			"tone": "good",
			"can_bypass": False,
			"bypass_labels": [],
		}

	return {"verdict": verdict, "rows": rows}


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


# ---------------------------------------------------------------------------
# reads → classify (impure)
# ---------------------------------------------------------------------------


def build_posture() -> dict:
	"""Read the site's ACTUAL auth surface + this app's state, then classify. Every read
	is defensive (a field/DocType absent on an older Frappe returns a falsy default), so
	the endpoint never 500s on a lean site."""
	from passkeys import boot

	settings = frappe.get_cached_doc("Passkey Settings")
	core_2fa = bool(cint(_system_setting("enable_two_factor_auth")))
	passkey_only_count, login_user_count = _adoption_counts()
	return classify_posture(
		{
			"first_factor": bool(cint(settings.login_with_passkey)),
			"second_factor": bool(cint(settings.passkey_as_second_factor)),
			"password_login_enabled": not bool(cint(_system_setting("disable_user_pass_login"))),
			"email_link_login": bool(cint(_system_setting("login_with_email_link"))),
			"social_providers": _enabled_social_providers(),
			"ldap_enabled": _ldap_enabled(),
			"core_2fa_enabled": core_2fa,
			"core_2fa_method": (_system_setting("two_factor_method") or None) if core_2fa else None,
			"passkey_only_user_count": passkey_only_count,
			"login_user_count": login_user_count,
			"enforcement_effective": boot._policy_effective(settings),
			"sign_count_hard_fail": bool(cint(settings.passkey_sign_count_hard_fail)),
			"reauth_window": cint(settings.passkey_reauth_window),
		}
	)


def _adoption_counts() -> tuple[int, int]:
	"""``(passkey_only_count, login_user_count)`` for the adoption row, counted over the
	SAME eligible population — enabled Users excluding Administrator and Guest.

	The denominator ``m`` always excluded Administrator/Guest and disabled users, but the
	numerator ``n`` used to count ``passkey_only_login`` handles over ALL users, so an
	Administrator or a disabled user with a passkey-only handle could push ``n`` above
	``m`` (n > m). Joining the handle count to the same eligible User set keeps n <= m."""
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
	try:
		return frappe.db.get_single_value("System Settings", field)
	except Exception:
		return None


def _enabled_social_providers() -> list:
	"""Display labels for enabled Social Login Keys (provider_name, else the enum
	provider, else the row name)."""
	try:
		rows = frappe.get_all(
			"Social Login Key",
			filters={"enable_social_login": 1},
			fields=["name", "provider_name", "social_login_provider"],
		)
	except Exception:
		return []
	labels = []
	for row in rows:
		label = row.get("provider_name") or row.get("social_login_provider") or row.get("name")
		if label:
			labels.append(str(label))
	return labels


def _ldap_enabled() -> bool:
	if not frappe.db.exists("DocType", "LDAP Settings"):
		return False
	try:
		return bool(cint(frappe.db.get_single_value("LDAP Settings", "enabled")))
	except Exception:
		return False
