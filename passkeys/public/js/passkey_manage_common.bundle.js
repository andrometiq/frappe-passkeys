// passkey_manage_common.bundle.js — pure logic for credential management, enrollment
// nudges and the settings UX, side-effect-free at load so `node --test` covers it. The
// DOM wiring lives in the desk/portal bundles, user_passkeys.js and passkey_settings.js.
// Exports CommonJS for node and `frappe.passkeys_manage_common` in the browser; it must
// load AFTER passkey_common.bundle.js.
//
// eslint-env browser, node
(function (root, factory) {
	"use strict";
	var api = factory();
	if (typeof module === "object" && module.exports) {
		module.exports = api; // node unit tests
	}
	if (typeof window !== "undefined") {
		window.frappe = window.frappe || {};
		window.frappe.passkeys_manage_common = api; // browser bundles
	}
})(typeof self !== "undefined" ? self : this, function () {
	"use strict";

	// ================================================================ wire seam
	var MANAGE_METHODS = {
		list: "passkeys.api.credentials.list_credentials",
		rename: "passkeys.api.credentials.rename_credential",
		del: "passkeys.api.credentials.delete_credential",
		setPasskeyOnly: "passkeys.api.credentials.set_passkey_only_login",
		beginRegistration: "passkeys.api.registration.begin_registration",
		verifyRegistration: "passkeys.api.registration.verify_registration",
		recordNudge: "passkeys.passkey.record_nudge",
		recordEnforcement: "passkeys.passkey.record_enforcement",
		getSignalData: "passkeys.passkey.get_signal_data",
		// admin enforcement-recovery (System-Manager-only; User-form Passkeys section)
		getUserEnforcementAdmin: "passkeys.enforcement_admin.get_user_enforcement_admin",
		setUserExemption: "passkeys.enforcement_admin.set_user_exemption",
		resetEnforcementGrace: "passkeys.enforcement_admin.reset_enforcement_grace",
	};

	// The confirm-ceremony action that sudo-gates the app's own management
	// surface: a live `passkeys.manage` window OR a fresh passkey
	// confirmation satisfies delete / explicit registration.
	var MANAGE_ACTION = "passkeys.manage";

	// record_nudge event enum.
	var NUDGE_EVENTS = { SHOWN: "shown", DECLINED: "declined", OPT_OUT: "opt_out" };

	// record_enforcement event enum. DEFER spends one grace login ("Remind me later");
	// INCAPABLE reports the device cannot create a passkey (admin advisory under
	// Block + Notify Admin).
	var ENFORCE_EVENTS = { DEFER: "defer", INCAPABLE: "incapable" };

	// localStorage key the login bundle sets after a hybrid (QR) assertion with
	// local isUVPAA (post-hybrid upsell).
	var UPSELL_FLAG_KEY = "passkey_upsell_add_local";

	var ZERO_AAGUID = "00000000-0000-0000-0000-000000000000";

	// ===================================================== translatable copy keys
	// English source strings; logic returns keys/args and the renderer calls __().
	var COPY = {
		// cards / empty state
		unknownProvider: "Unknown provider",
		syncedBadge: "Synced",
		deviceBoundBadge: "Device-bound",
		syncedHint: "Available on your other devices",
		deviceBoundHint: "Stays on this device only",
		emptyTitle: "Create a passkey",
		emptyBody:
			"A passkey lets you sign in with your fingerprint, face, screen lock, or a " +
			"security key — no password to remember or type.",
		addButton: "Add a passkey",
		renameAction: "Rename passkey {0}",
		deleteAction: "Delete passkey {0}",
		renamePrompt: "New name for this passkey",
		deleteConfirmTitle: "Remove this passkey?",
		deleteConfirmBody: "You won't be able to sign in with {0} after this.",
		deleteConfirmCta: "Remove passkey",
		flaggedBanner: "This passkey was flagged and disabled for your security.",
		disabledBadge: "Disabled",
		createdLabel: "Added",
		lastUsedLabel: "Last used",
		lastUsedNever: "Never used yet",
		// friendly ceremony errors
		alreadyRegistered: "This device already has a passkey for this account.",
		addExpired: "That took too long — please try again.",
		addFailed: "Couldn't add a passkey — please try again.",
		// nudge
		nudgeTitle: "Sign in faster next time",
		nudgeBody:
			"Add a passkey and skip the password next time — sign in with your fingerprint, " +
			"face, or screen lock instead.",
		nudgeCta: "Create a passkey",
		nudgeLater: "Not now",
		nudgeNever: "Don't ask again",
		nudgeSaveFailed: "Couldn't save your choice — please try again.",
		upsellTitle: "Add a passkey to this device",
		upsellBody:
			"You just signed in from another device. Add a passkey here to sign in " +
			"directly next time.",
		// enforcement interstitial (honest, guilt-free copy — FIDO no-dark-pattern rule)
		enforceTitle: "Set up a passkey to continue",
		enforceBody:
			"Your organization requires a passkey to keep signing in. It only takes a " +
			"moment — use your fingerprint, face, screen lock, or a security key.",
		enforceRemindLater: "Remind me later (sign-ins left: {0})",
		enforceCantSetUp: "I can't set one up here",
		enforceBlockedNotice:
			"We've let your administrator know. Please contact them to finish signing in.",
		enforceRetry: "Try passkey setup again",
		enforceSignOut: "Sign out",
		enforceContactAdmin: "Contact administrator",
		// admin enforcement-recovery (User-form Passkeys section, System-Manager-only)
		enforceAdminHeading: "Passkey enrollment enforcement",
		enforceAdminExempt: "Exempt from passkey enforcement",
		enforceAdminUnexempt: "Remove enforcement exemption",
		enforceAdminReset: "Reset grace logins",
		enforceAdminGrace: "Grace logins used: {0} of {1} ({2} remaining).",
		enforceAdminStateExempt: "Exempt from enforcement",
		enforceAdminStateEnforced: "In scope — must enroll a passkey",
		enforceAdminStateSatisfied: "In scope — already has a passkey",
		enforceAdminStateNotScope: "Not in enforcement scope",
		enforceAdminExemptDone: "{0} is now exempt from passkey enforcement.",
		enforceAdminUnexemptDone: "Exemption removed — {0} is enforced again.",
		enforceAdminResetDone: "Grace reset — {0} sign-ins to enroll before it blocks.",
		enforceAdminFailed: "Couldn't update enforcement for this user — please try again.",
		// passkey-only switch
		passkeyOnlyLabel: "Passwordless login only",
		passkeyOnlyHelp:
			"Turn off password sign-in for your account. Needs at least two passkeys so a " +
			"lost device never locks you out.",
		passkeyOnlyNeedsTwo:
			"Add at least two enabled passkeys before turning off password sign-in.",
		// settings banners — keyed; args filled by the matrix
		rpIdOneWayDoor:
			"Changing the RP ID invalidates every existing passkey. This cannot be undone.",
		rpIdUnresolved:
			"No Relying Party ID can be resolved, so passkeys cannot be enabled and sign-in " +
			"will fail. Fix it one of two ways: set host_name in the site config " +
			"(site_config.json) to this site's domain, or enter an explicit Passkey RP ID " +
			"(a bare host name like {0}) in the field below.",
		hostMismatch:
			"The resolved RP ID / origins do not match this site's current host — passkey " +
			"sign-in will fail here until this is corrected.",
		twofaRequiresCore:
			"Passkey second factor needs core two-factor authentication enabled first.",
		notifyOffWeakens:
			"Turning off change notifications removes the main safeguard against a hijacked " +
			"session silently adding a passkey.",
		deadTwofaCombo:
			"Password login is disabled site-wide, so passkey second factor can never run for " +
			"password logins.",
		strandsPasskeyOnlyUsers:
			"This change would leave {0} passwordless-only user(s) with no way to sign in. " +
			"Clear their passwordless-only flag first.",
		allModesOff:
			"Both passkey login modes are off — the login-page passkey UI is hidden and no new " +
			"passkeys can be used to sign in. Existing passkeys are preserved.",
		// enrollment ladder (policy Select + enforcement scope/escape hatches)
		enforceNoDate:
			"Enrollment Policy 'Enforce After Date' needs an Enforce After date — Save will fail " +
			"until you set it (or choose 'Enforce' to enforce immediately).",
		enforceNoMode:
			"Enrollment enforcement has no effect while both passkey login modes are off. Enable a " +
			"passkey login mode for the policy to apply.",
		enforcePrivilegedOutside:
			"Privileged users (System Manager) are outside passkey enforcement. Administrators are " +
			"the accounts attackers target first — industry practice enforces them first.",
		enforceEmptyRoles:
			"Enforcement scope is 'Selected Roles' but no roles are listed, so the policy applies " +
			"to nobody. Add the roles to enforce, or switch the scope to 'All Users'.",
		enforceBlockIncapable:
			"Incapable Device Policy is 'Block + Notify Admin': users on devices that cannot create " +
			"a passkey (and cannot use a phone) will be blocked rather than nudged.",
		enforcePreview:
			"This policy would require a passkey from {0} in-scope user(s) who do not have one yet.",
	};

	// ------------------------------------------------------------ tiny formatter
	// {0}/{1} placeholder fill for pure logic; the DOM layer translates the key first.
	function format(str, args) {
		if (!args || !args.length) return str;
		return String(str).replace(/\{(\d+)\}/g, function (m, i) {
			var v = args[Number(i)];
			return v === undefined || v === null ? "" : String(v);
		});
	}

	// ---------------------------------------------------------- provider lookup
	// Card provider name: server cred.provider, else aaguidMap[aaguid], else null (Unknown).
	// A zero / empty AAGUID is not an error (Safari ships none).
	function providerFor(cred, aaguidMap) {
		cred = cred || {};
		if (cred.provider) return String(cred.provider);
		var a = String(cred.aaguid || "").toLowerCase();
		if (!a || a === ZERO_AAGUID) return null;
		if (aaguidMap && Object.prototype.hasOwnProperty.call(aaguidMap, a)) {
			var v = aaguidMap[a];
			if (typeof v === "string") return v;
			if (v && v.name) return String(v.name);
		}
		return null;
	}

	// Synced (multi-device / backup_state) vs Device-bound badge.
	function backupBadge(cred) {
		var synced = !!(cred && (cred.backup_state === 1 || cred.backup_state === true));
		return {
			synced: synced,
			key: synced ? COPY.syncedBadge : COPY.deviceBoundBadge,
			hintKey: synced ? COPY.syncedHint : COPY.deviceBoundHint,
		};
	}

	function isTruthy(v) {
		return v === 1 || v === true || v === "1";
	}

	// Accessible name for an icon-only card action ("Rename passkey ⟨label⟩").
	function accessibleActionName(kind, label, translate) {
		var key = kind === "delete" ? COPY.deleteAction : COPY.renameAction;
		var tr = typeof translate === "function" ? translate : function (s) { return s; };
		return format(tr(key), [label || ""]);
	}

	// Per-credential card view-model. Values stay raw (the DOM layer formats and escapes).
	function credentialViewModel(cred, opts) {
		opts = opts || {};
		cred = cred || {};
		var tr = typeof opts.translate === "function" ? opts.translate : function (s) { return s; };
		var label = cred.label || providerFor(cred, opts.aaguidMap) || tr(COPY.unknownProvider);
		var providerName = providerFor(cred, opts.aaguidMap);
		return {
			name: cred.name,
			label: label,
			providerName: providerName, // null ⇒ show generic glyph + Unknown provider
			hasProvider: providerName !== null,
			unknownProviderKey: COPY.unknownProvider,
			badge: backupBadge(cred),
			enabled: cred.enabled === undefined ? true : isTruthy(cred.enabled),
			flagged: isTruthy(cred.flagged),
			flaggedReason: cred.flagged_reason || null,
			discoverable: cred.discoverable || "Unknown",
			created: cred.creation || null,
			lastUsed: cred.last_used_at || null,
			a11y: {
				rename: accessibleActionName("rename", label, tr),
				del: accessibleActionName("delete", label, tr),
			},
		};
	}

	// ------------------------------------------------------- nudge decisions
	// The server owns the cadence (boot.nudge_state.eligible); the client adds capability.
	function nudgeDecision(boot, caps) {
		boot = boot || {};
		caps = caps || {};
		var supported = caps.supported !== false; // unknown counts as supported
		var eligible = !!boot.nudge_state && boot.nudge_state.eligible === true;

		var out = { showNudge: false, allowConditionalCreate: false, reason: "", eligible: eligible };
		if (!eligible) out.reason = "server_ineligible";
		else if (!supported) out.reason = "unsupported";
		else { out.showNudge = true; out.reason = "eligible"; }

		// Conditional create also needs a PASSWORD-seeded login window: session age alone
		// cannot tell a password login from an email-link one.
		out.allowConditionalCreate =
			eligible &&
			caps.conditionalCreate === true &&
			boot.post_login_method === "password" &&
			boot.conditional_create === true;

		return out;
	}

	// The post-login enforcement decision. The server owns the verdict (`boot.enforcement`);
	// the client adds only device capability, which the server cannot know. Returns:
	//   show        — surface an interstitial at all
	//   variant     — "enforce" (the blocking/skippable enrollment gate) or "nudge"
	//                 (an incapable device under Degrade, subject to server nudge cadence)
	//   blocking    — the enforce variant is non-dismissible (grace exhausted, or the
	//                 admin chose Block + Notify Admin for an incapable device)
	//   allowHybrid — offer the phone/QR enrollment path
	//   notifyAdmin — record the incapable event so the admin is alerted (Block + Notify)
	//   graceRemaining — honest "N sign-ins left" for the skippable copy
	//   reason      — machine-readable, for tests/telemetry
	//   boot: frappe.boot.passkeys (needs .enforcement + .credential_count)
	//   caps: client capability probe (supported / uvpaa / hybrid)
	function enforcementDecision(boot, caps) {
		boot = boot || {};
		caps = caps || {};
		var enf = boot.enforcement || {};
		var out = {
			show: false, blocking: false, variant: "", allowHybrid: false,
			notifyAdmin: false, graceRemaining: 0, reason: "",
		};
		// Only the server's enforce rung engages this surface; Off/Nudge/pre-date
		// (effective !== "enforce") or out-of-scope ⇒ the nudge path owns things.
		if (enf.effective !== "enforce" || !enf.in_scope) { out.reason = "not_enforcing"; return out; }
		// Already holds a passkey ⇒ enforcement satisfied, nothing to prompt.
		var count = typeof boot.credential_count === "number" ? boot.credential_count : 0;
		if (count > 0) { out.reason = "satisfied"; return out; }

		out.graceRemaining = typeof enf.grace_remaining === "number" ? enf.grace_remaining : 0;
		out.allowHybrid = enf.allow_hybrid !== false; // default on unless server says false
		var supported = caps.supported !== false; // unknown counts as capable
		var uvpaaOk = caps.uvpaa !== false; // unknown counts as capable
		var hybridOk = caps.hybrid !== false; // unknown counts as capable
		// Enroll can fall through to a phone/QR (hybrid) when there's no platform
		// authenticator — so "capable to enroll" is UVPAA OR (hybrid allowed ∧ hybrid).
		var canEnroll = supported && (uvpaaOk || (out.allowHybrid && hybridOk));

		if (canEnroll) {
			out.show = true;
			out.variant = "enforce";
			out.blocking = enf.blocking === true;
			out.reason = out.blocking ? "enforce_blocking" : "enforce_grace";
			return out;
		}
		// Genuinely incapable device — never a hard lockout by default.
		if (enf.incapable_policy === "block_notify") {
			out.show = true;
			out.variant = "enforce";
			out.blocking = true;
			out.notifyAdmin = true;
			out.reason = "incapable_block_notify";
		} else {
			// Degrade shares the ordinary server-owned nudge cadence.
			out.show = enf.degrade_nudge_eligible === true;
			out.variant = "nudge";
			out.blocking = false;
			out.reason = out.show ? "incapable_degrade" : "incapable_degrade_capped";
		}
		return out;
	}

	// ---------------------------------------------- admin enforcement recovery
	// Show the User-form enforcement-recovery controls only under an enforcement policy.
	// The policy is site-wide, so the admin's own boot value decides.
	function shouldShowEnforcementAdmin(boot) {
		var policy = boot && boot.enforcement && boot.enforcement.policy;
		return policy === "Enforce" || policy === "Enforce After Date";
	}

	// View-model for the admin enforcement-recovery controls (get_user_enforcement_admin).
	function enforcementAdminViewModel(state) {
		state = state || {};
		var exempt = state.exempt === true;
		var inScope = state.in_scope === true;
		var hasCred = cint(state.credential_count) > 0;
		var graceUsed = cint(state.grace_used);
		var indicator;
		if (exempt) indicator = { color: "green", textKey: "enforceAdminStateExempt" };
		else if (inScope && hasCred) indicator = { color: "green", textKey: "enforceAdminStateSatisfied" };
		else if (inScope) indicator = { color: "orange", textKey: "enforceAdminStateEnforced" };
		else indicator = { color: "gray", textKey: "enforceAdminStateNotScope" };
		return {
			exempt: exempt,
			inScope: inScope,
			graceUsed: graceUsed,
			graceTotal: cint(state.grace_total),
			graceRemaining: cint(state.grace_remaining),
			// The exempt toggle: label flips, and `nextExemptValue` is what to POST.
			exemptButtonKey: exempt ? "enforceAdminUnexempt" : "enforceAdminExempt",
			exemptButtonPrimary: !exempt,
			nextExemptValue: !exempt,
			// Reset is a no-op when no grace has been spent — disable it then.
			resetDisabled: graceUsed <= 0,
			indicator: indicator,
		};
	}

	function cint(v) { var n = parseInt(v, 10); return isNaN(n) ? 0 : n; }

	// Post-hybrid upsell: after a QR sign-in the login bundle sets UPSELL_FLAG_KEY; offer
	// "add a passkey to this device" under the server's upsell cadence, which has no
	// 0-credentials gate. `storageGet(key)` is injected so the logic stays browser-free.
	function upsellDecision(boot, caps, storageGet) {
		boot = boot || {};
		caps = caps || {};
		var flagged = false;
		try {
			flagged = typeof storageGet === "function" && storageGet(UPSELL_FLAG_KEY) === "1";
		} catch (e) {
			flagged = false;
		}
		var supported = caps.supported !== false;
		var uvpaaOk = caps.uvpaa !== false; // unknown ⇒ still offer (local sheet decides)
		var cadence = boot.upsell_eligible === true;

		var out = { showUpsell: false, reason: "" };
		if (!flagged) out.reason = "no_flag";
		else if (!cadence) out.reason = "cadence_capped";
		else if (!supported) out.reason = "unsupported";
		else if (!uvpaaOk) out.reason = "no_platform_authenticator";
		else {
			out.showUpsell = true;
			out.reason = "eligible";
		}
		return out;
	}

	// ---------------------------------------------------- settings banners
	// Banners ({level, key, args}) for the Passkey Settings values. Banners that need
	// server context are emitted only when `ctx` carries it.
	//   doc: { login_with_passkey, passkey_as_second_factor, passkey_notify_on_change,
	//          passkey_rp_id, passkey_origins }
	//   ctx: { currentHost, currentOrigin, resolvedRpId, resolvedOrigins, coreTwoFactor,
	//          disablePassLogin, passkeyOnlyUserCount }
	function settingsBanners(doc, ctx) {
		doc = doc || {};
		ctx = ctx || {};
		var banners = [];
		var firstFactor = isTruthy(doc.login_with_passkey);
		var secondFactor = isTruthy(doc.passkey_as_second_factor);
		var anyMode = firstFactor || secondFactor;

		// No RP ID while enabling a mode: Save will fail (_validate_enablement), so say how
		// to fix it now. `resolvedRpId` is server-truth, never the browser host.
		if (anyMode && !ctx.resolvedRpId) {
			banners.push({ level: "error", key: COPY.rpIdUnresolved, args: [ctx.currentHost || ""] });
		}

		// This page's origin is not trusted, so ceremonies here will fail. Only once an RP ID
		// resolves; otherwise rpIdUnresolved is the real story.
		if (
			ctx.resolvedRpId &&
			ctx.currentOrigin &&
			Array.isArray(ctx.resolvedOrigins) &&
			ctx.resolvedOrigins.length &&
			!originsIncludeOrigin(ctx.resolvedOrigins, ctx.currentOrigin)
		) {
			banners.push({ level: "error", key: COPY.hostMismatch, args: [ctx.resolvedRpId || ""] });
		}

		// Validator: 2FA needs core two-factor ON. Client pre-warn.
		if (secondFactor && ctx.coreTwoFactor !== undefined && !isTruthy(ctx.coreTwoFactor)) {
			banners.push({ level: "error", key: COPY.twofaRequiresCore });
		}

		// warning: dead 2FA combo under site disable_user_pass_login.
		if (secondFactor && ctx.disablePassLogin !== undefined && isTruthy(ctx.disablePassLogin)) {
			banners.push({ level: "warning", key: COPY.deadTwofaCombo });
		}

		// warning: notifications off weakens the hijack safeguard.
		if (anyMode && doc.passkey_notify_on_change !== undefined && !isTruthy(doc.passkey_notify_on_change)) {
			banners.push({ level: "warning", key: COPY.notifyOffWeakens });
		}

		// generalized guard pre-warn: no passkey-capable mode left
		// while passkey-only users exist (server REFUSES the save — this is a heads-up).
		if (!anyMode && (ctx.passkeyOnlyUserCount || 0) > 0) {
			banners.push({
				level: "error",
				key: COPY.strandsPasskeyOnlyUsers,
				args: [ctx.passkeyOnlyUserCount],
			});
		}

		// ---- enrollment ladder (policy Select + enforcement scope) ----
		var policy = doc.passkey_enrollment_policy || "Nudge";
		var enforcing = policy === "Enforce" || policy === "Enforce After Date";

		// Enforce After Date with no date — Save WILL fail (validator throws).
		if (policy === "Enforce After Date" && !doc.passkey_enforce_after) {
			banners.push({ level: "error", key: COPY.enforceNoDate });
		}
		if (enforcing) {
			// Inert policy: enforcing while no passkey login mode is on.
			if (!anyMode) banners.push({ level: "warning", key: COPY.enforceNoMode });
			// Privileged accounts should remain inside enforcement scope.
			if (!isTruthy(doc.passkey_enforce_privileged_always)) {
				banners.push({ level: "warning", key: COPY.enforcePrivilegedOutside });
			}
			// Selected-roles scope with an empty role list enforces against nobody.
			if (doc.passkey_enforce_scope === "Selected Roles" && !roleNames(doc.passkey_enforce_roles).length) {
				banners.push({ level: "warning", key: COPY.enforceEmptyRoles });
			}
			// Block + Notify can hard-lock genuinely incapable devices.
			if (doc.passkey_enforce_incapable === "Block + Notify Admin") {
				banners.push({ level: "warning", key: COPY.enforceBlockIncapable });
			}
			// Report-only preview: how many in-scope users would be required to enroll
			// (server-supplied — only shown when the count context is present).
			if (typeof ctx.wouldBeBlockedCount === "number") {
				banners.push({ level: "info", key: COPY.enforcePreview, args: [ctx.wouldBeBlockedCount] });
			}
		}

		// "pause": both modes off is legal but the UI removes itself.
		if (!anyMode) {
			banners.push({ level: "info", key: COPY.allModesOff });
		}

		return banners;
	}

	// Normalize a Table-MultiSelect value to an array of role-name strings. Accepts
	// child rows ({role}), plain strings, or a missing table (⇒ []).
	function roleNames(rows) {
		if (!Array.isArray(rows)) return [];
		return rows
			.map(function (r) { return typeof r === "string" ? r : r && r.role; })
			.filter(function (r) { return !!r; });
	}

	// Client mirror of policy.resolve_origins: the configured site origin, then the explicit
	// passkey_origins lines (deduped). The RP ID is never an origin.
	function deriveOrigins(raw, configuredSiteOrigin) {
		var origins = configuredSiteOrigin ? [String(configuredSiteOrigin).trim()] : [];
		String(raw || "").split(/\r?\n/).forEach(function (line) {
			line = line.trim();
			if (line && origins.indexOf(line) === -1) origins.push(line);
		});
		return origins;
	}

	// The passkey-only server floor is two ENABLED credentials when turning the flag
	// on. A user already in passkey-only mode must always be able to turn it off, even
	// if a credential was disabled out of band.
	function passkeyOnlyAvailability(enabledCount, current) {
		enabledCount = cint(enabledCount);
		var needsTwo = !current && enabledCount < 2;
		return {
			enabledCount: enabledCount,
			disabled: needsTwo,
			helpKey: needsTwo ? "passkeyOnlyNeedsTwo" : "passkeyOnlyHelp",
		};
	}

	// Match well_known._fingerprints exactly: optional SHA256 label and colons are
	// presentation only; after removing them each non-empty line must be 64 hex chars.
	function validateAndroidFingerprints(raw) {
		var invalid = [];
		var normalized = [];
		String(raw || "").split(/\r?\n/).forEach(function (original) {
			var line = original.replace(/^\s*sha-?256\s*[:=]?/i, "").trim();
			if (!line) return;
			var hex = line.replace(/:/g, "");
			if (!/^[0-9a-f]{64}$/i.test(hex)) { invalid.push(original.trim()); return; }
			hex = hex.toUpperCase();
			var grouped = [];
			for (var i = 0; i < hex.length; i += 2) grouped.push(hex.slice(i, i + 2));
			var value = grouped.join(":");
			if (normalized.indexOf(value) === -1) normalized.push(value);
		});
		return { valid: invalid.length === 0, invalid: invalid, normalized: normalized };
	}

	// A server grace verdict changes after a successful defer, so remaining-count plus
	// user is a stable idempotency key for retries/reloads within one browser session.
	function enforcementDeferKey(user, enforcement) {
		enforcement = enforcement || {};
		return "passkey_enforcement_defer:" + encodeURIComponent(String(user || "current")) +
			":" + encodeURIComponent(String(enforcement.policy || enforcement.effective || "enforce")) +
			":" + cint(enforcement.graceRemaining !== undefined
				? enforcement.graceRemaining : enforcement.grace_remaining);
	}

	// Run one asynchronous event per key. sessionStorage survives page reloads; the
	// closure covers browsers where storage is unavailable. Failed work clears the key
	// so a genuine transport/server failure can be retried.
	function createSessionEventRecorder(storage) {
		var memory = {};
		function read(key) {
			try { return storage && storage.getItem(key); } catch (e) { return null; }
		}
		function write(key, value) {
			try { if (storage) storage.setItem(key, value); } catch (e) { /* storage denied */ }
		}
		function clear(key) {
			delete memory[key];
			try { if (storage) storage.removeItem(key); } catch (e) { /* storage denied */ }
		}
		return function (key, task) {
			if (memory[key] || read(key)) return Promise.resolve({ skipped: true });
			memory[key] = true;
			write(key, "pending");
			var pending;
			try { pending = task(); }
			catch (error) { clear(key); return Promise.reject(error); }
			return Promise.resolve(pending).then(function (result) {
				write(key, "done");
				return result;
			}, function (error) {
				clear(key);
				throw error;
			});
		};
	}

	// Exact-origin membership (scheme, host and port), as the server matches
	// clientDataJSON.origin against its allowlist.
	function originsIncludeOrigin(origins, origin) {
		var target = canonicalOrigin(origin);
		return !!target && origins.some(function (candidate) {
			return canonicalOrigin(candidate) === target;
		});
	}
	// Browser-canonical scheme://host[:port] (default port dropped), or null.
	function canonicalOrigin(origin) {
		try {
			var canonical = new URL(String(origin || "").trim()).origin;
			return canonical === "null" ? null : canonical;
		} catch (e) {
			return null;
		}
	}

	// ---------------------------------------------------- security posture panel
	// Orders the server's translated posture rows (posture.build_posture): severity
	// high→info, the detectability disclaimer (detectable === false) always last. No copy here.
	var POSTURE_SEVERITY_RANK = { high: 0, medium: 1, low: 2, info: 3 };

	function posturePanel(response) {
		response = response || {};
		var verdict = response.verdict || {};
		var rows = Array.isArray(response.rows) ? response.rows.slice() : [];
		// Stable sort keeps server order within a bucket.
		rows.sort(function (a, b) {
			var da = a && a.detectable === false ? 1 : 0;
			var db = b && b.detectable === false ? 1 : 0;
			if (da !== db) return da - db;
			var ra = POSTURE_SEVERITY_RANK[a && a.severity];
			var rb = POSTURE_SEVERITY_RANK[b && b.severity];
			if (ra === undefined) ra = 9;
			if (rb === undefined) rb = 9;
			return ra - rb;
		});
		return {
			headline: {
				text: verdict.headline || "",
				tone: verdict.tone || "info", // "high" | "good" | "info"
				canBypass: verdict.can_bypass === true,
			},
			rows: rows.map(function (r) {
				r = r || {};
				return {
					code: r.code || "",
					severity: r.severity || "info",
					what: r.what || "",
					why: r.why || "",
					recommendation: r.recommendation || "",
					detectable: r.detectable !== false,
				};
			}),
		};
	}

	// The row mark the settings report paints; undetectable rows are always a "note".
	var POSTURE_ROW_MARK = { high: "flag", medium: "warn", low: "tune", info: "note" };

	function postureRowMark(row) {
		row = row || {};
		if (row.detectable === false) return "note";
		return POSTURE_ROW_MARK[row.severity] || "note";
	}

	// posturePanel with each row's mark: the settings-report view-model.
	function postureReport(response) {
		var panel = posturePanel(response);
		panel.rows.forEach(function (r) { r.mark = postureRowMark(r); });
		return panel;
	}

	// ---------------------------------------------------------- signal payloads
	// Shape a signalAllAcceptedCredentials payload from a verify_registration
	// signal block or a get_signal_data response. Returns null when
	// there is nothing to signal (caller then no-ops — fire-and-forget).
	function signalPayload(data) {
		var s = data && (data.signal || data);
		if (!s) return null;
		var userHandle = s.user_handle || s.userHandle || null;
		var ids = s.credential_ids || s.credentialIds || null;
		if (!userHandle || !Array.isArray(ids)) return null;
		// An empty array is intentional: after the last passkey is deleted the provider should
		// hide them all. Callers signal only after a successful server read, so a failed list
		// never sends [].
		return { userHandle: userHandle, allAcceptedCredentialIds: ids.slice() };
	}

	// Shape a signalCurrentUserDetails payload from a get_signal_data response or a
	// verify_registration signal block. Returns null when there's nothing to sync.
	// signalCurrentUserDetails needs BOTH name + displayName; if the server sent only one,
	// mirror it into the other so the provider's account-chooser label is never blanked.
	function currentUserDetailsPayload(data) {
		var s = data && (data.signal || data);
		if (!s) return null;
		var userHandle = s.user_handle || s.userHandle || null;
		var name = s.name || null;
		var displayName = s.display_name || s.displayName || null;
		if (!userHandle || (!name && !displayName)) return null;
		return { userHandle: userHandle, name: name || displayName, displayName: displayName || name };
	}

	// Fire both WebAuthn Signal API updates from one parity-correct seam. Registration
	// can pass its verify payload; deletion passes get_signal_data. An empty accepted-id
	// list is intentional after the final credential is removed. The native calls remain
	// best-effort and are never awaited on a mutation's critical path.
	function signalCredentialState(PKC, data, defaultRpId) {
		var source = data && (data.signal || data);
		var rpId = source && (source.rp_id || source.rpId) || defaultRpId || null;
		var result = { accepted: false, details: false };
		if (!PKC || !rpId) return result;
		var accepted = signalPayload(data);
		if (accepted && typeof PKC.signalAllAcceptedCredentials === "function") {
			try {
				var p = PKC.signalAllAcceptedCredentials({
					rpId: rpId,
					userId: accepted.userHandle,
					allAcceptedCredentialIds: accepted.allAcceptedCredentialIds,
				});
				if (p && typeof p.catch === "function") p.catch(function () {});
				result.accepted = true;
			} catch (e) { /* unsupported/broken implementation */ }
		}
		var details = currentUserDetailsPayload(data);
		if (details && typeof PKC.signalCurrentUserDetails === "function") {
			try {
				var q = PKC.signalCurrentUserDetails({
					rpId: rpId,
					userId: details.userHandle,
					name: details.name,
					displayName: details.displayName,
				});
				if (q && typeof q.catch === "function") q.catch(function () {});
				result.details = true;
			} catch (e2) { /* unsupported/broken implementation */ }
		}
		return result;
	}

	return {
		// wire seam
		MANAGE_METHODS: MANAGE_METHODS,
		MANAGE_ACTION: MANAGE_ACTION,
		NUDGE_EVENTS: NUDGE_EVENTS,
		ENFORCE_EVENTS: ENFORCE_EVENTS,
		UPSELL_FLAG_KEY: UPSELL_FLAG_KEY,
		ZERO_AAGUID: ZERO_AAGUID,
		COPY: COPY,
		// pure helpers
		format: format,
		providerFor: providerFor,
		backupBadge: backupBadge,
		accessibleActionName: accessibleActionName,
		credentialViewModel: credentialViewModel,
		nudgeDecision: nudgeDecision,
		enforcementDecision: enforcementDecision,
		shouldShowEnforcementAdmin: shouldShowEnforcementAdmin,
		enforcementAdminViewModel: enforcementAdminViewModel,
		upsellDecision: upsellDecision,
		settingsBanners: settingsBanners,
		roleNames: roleNames,
		deriveOrigins: deriveOrigins,
		passkeyOnlyAvailability: passkeyOnlyAvailability,
		validateAndroidFingerprints: validateAndroidFingerprints,
		enforcementDeferKey: enforcementDeferKey,
		createSessionEventRecorder: createSessionEventRecorder,
		originsIncludeOrigin: originsIncludeOrigin,
		canonicalOrigin: canonicalOrigin,
		posturePanel: posturePanel,
		postureRowMark: postureRowMark,
		postureReport: postureReport,
		signalPayload: signalPayload,
		currentUserDetailsPayload: currentUserDetailsPayload,
		signalCredentialState: signalCredentialState,
	};
});
