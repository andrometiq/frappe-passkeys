// passkey_manage_common.bundle.js — shared PURE logic for the credential-management
// surfaces + enrollment nudges + settings UX. Destination on core merge:
// frappe/public/js/frappe/passkey/ (frappe.ui.passkey.*).
//
// Like passkey_common.bundle.js this module is deliberately framework-light and
// side-effect-free at load time so its pure logic (card view-models, provider
// resolution, the nudge cadence decision, the post-hybrid upsell gate, the
// settings-banner matrix, the last-method delete guard, signal-payload shaping)
// is unit-testable under plain `node --test` WITHOUT a bench and WITHOUT jsdom.
//
// The DOM/frappe wiring (frappe.ui.Dialog, fetch, navigator.credentials, the
// User-form / navbar / portal renderers, the Passkey Settings form glue) lives in
// passkey_desk.bundle.js / user_passkeys.js / passkey_portal.bundle.js /
// passkey_settings.js, which pass real values into these pure functions.
//
// Dual export (UMD-lite): CommonJS `module.exports` for node tests; browser
// global `frappe.passkeys_manage_common` for the bundles (loaded as its own
// app_include_js/web_include_js entry AFTER passkey_common.bundle.js).
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
	// Whitelisted server method dotted-paths the management UI calls. Kept here so
	// the parallel server phase can grep the exact strings. The credential/
	// registration rows are the EXISTING P2b endpoints (passkeys/api/*.py); the
	// nudge rows are REQUESTED endpoints — see the build manifest.
	var MANAGE_METHODS = {
		list: "passkeys.api.credentials.list_credentials",
		rename: "passkeys.api.credentials.rename_credential",
		del: "passkeys.api.credentials.delete_credential",
		setPasskeyOnly: "passkeys.api.credentials.set_passkey_only_login",
		beginRegistration: "passkeys.api.registration.begin_registration",
		verifyRegistration: "passkeys.api.registration.verify_registration",
		// The server phase built these on passkey.py.
		recordNudge: "passkeys.passkey.record_nudge",
		recordEnforcement: "passkeys.passkey.record_enforcement",
		getSignalData: "passkeys.passkey.get_signal_data",
	};

	// The confirm-ceremony action that sudo-gates the app's own management
	// surface: a live `passkeys.manage` window OR a fresh passkey
	// confirmation satisfies delete / explicit registration.
	var MANAGE_ACTION = "passkeys.manage";

	// The dedicated per-user passkey-grant action for the passkey-only switch.
	// set_passkey_only_login accepts a passkey grant ONLY.
	var PASSKEY_ONLY_ACTION = "passkeys.set_passkey_only_login";

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
	// English source strings (the DOM layer wraps each with __()). Grouped so the
	// server phase can mirror them into translations/{lang}.csv. Logic here
	// never bakes a language in — it returns keys/args, the renderer translates.
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
		// last-method guard
		lastMethodBlocked:
			"This is your only passkey and passwordless login is on for your account — " +
			"add another passkey (or turn off passkey-only login) before removing it.",
		// nudge
		nudgeTitle: "Sign in faster next time",
		nudgeBody:
			"Add a passkey and skip the password next time — sign in with your fingerprint, " +
			"face, or screen lock instead.",
		nudgeCta: "Create a passkey",
		nudgeLater: "Not now",
		nudgeNever: "Don't ask again",
		upsellTitle: "Add a passkey to this device",
		upsellBody:
			"You just signed in from another device. Add a passkey here to sign in " +
			"directly next time.",
		// enforcement interstitial (honest, guilt-free copy — FIDO no-dark-pattern rule)
		enforceTitle: "Set up a passkey to continue",
		enforceBody:
			"Your organization requires a passkey to keep signing in. It only takes a " +
			"moment — use your fingerprint, face, screen lock, or a security key.",
		enforceRemindLater: "Remind me later ({0} sign-ins left)",
		enforceCantSetUp: "I can't set one up here",
		enforceBlockedNotice:
			"We've let your administrator know. Please contact them to finish signing in.",
		// passkey-only switch
		passkeyOnlyLabel: "Passwordless login only",
		passkeyOnlyHelp:
			"Turn off password sign-in for your account. Needs at least two passkeys so a " +
			"lost device never locks you out.",
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
		enforceSelfLockout:
			"System Manager is not in the exempt roles while enforcing for all users — an " +
			"administrator on a device that cannot create a passkey could be locked out. Keep " +
			"System Manager exempt as a break-glass unless you are certain.",
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
	// Minimal {0}/{1} placeholder fill so pure logic can build accessible names
	// without depending on frappe's __() at test time. The DOM layer still passes
	// each COPY key through __() first (frappe's __ does the same placeholder fill).
	function format(str, args) {
		if (!args || !args.length) return str;
		return String(str).replace(/\{(\d+)\}/g, function (m, i) {
			var v = args[Number(i)];
			return v === undefined || v === null ? "" : String(v);
		});
	}

	// ---------------------------------------------------------- provider lookup
	// Card provider name. Preference order:
	//   1. server-supplied cred.provider (single source of truth = aaguid.py) —
	//      preferred so the client never ships a second copy of the snapshot;
	//   2. an injected client aaguidMap[aaguid] (release asset), when present;
	//   3. null  ⇒ caller shows the generic glyph + "Unknown provider".
	// A zero / empty AAGUID is NEVER an error (Safari ships none) — just Unknown.
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
	function accessibleActionName(kind, label) {
		var key = kind === "delete" ? COPY.deleteAction : COPY.renameAction;
		return format(key, [label || ""]);
	}

	// A per-credential view-model the card renderers consume. Carries RAW values
	// (dates stay raw so the renderer can use frappe.datetime) + pre-built
	// accessible names + badge + provider. Escaping happens in the DOM layer.
	function credentialViewModel(cred, opts) {
		opts = opts || {};
		cred = cred || {};
		var label = cred.label || providerFor(cred, opts.aaguidMap) || COPY.unknownProvider;
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
				rename: accessibleActionName("rename", label),
				del: accessibleActionName("delete", label),
			},
		};
	}

	// ------------------------------------------------------- nudge cadence
	// Whether the cooldown window has elapsed since the last nudge. `cooldownDays`
	// is the `passkey_nudge_cooldown_days` knob (default 30). Never shown ⇒
	// eligible. An unparseable timestamp is treated as never-shown (fail toward the
	// adoption lever, bounded by the decline cap).
	function cooldownElapsed(lastShownIso, cooldownDays, now) {
		if (!lastShownIso) return true;
		var then = Date.parse(lastShownIso);
		if (isNaN(then)) return true;
		now = typeof now === "number" ? now : Date.now();
		var days = typeof cooldownDays === "number" ? cooldownDays : 30;
		return now - then >= days * 24 * 60 * 60 * 1000;
	}

	function nudgeState(boot) {
		var s = (boot && boot.nudge_state) || {};
		return {
			declines: typeof s.declines === "number" ? s.declines : 0,
			lastShown: s.last_shown || null,
			optOut: isTruthy(s.opt_out),
		};
	}

	function nudgeKnobs(boot) {
		var st = (boot && boot.settings) || {};
		return {
			nudgeEnabled: isTruthy(st.nudge_enabled),
			conditionalCreate: isTruthy(st.conditional_create),
			maxPrompts: typeof st.nudge_max_prompts === "number" ? st.nudge_max_prompts : 3,
			cooldownDays: typeof st.nudge_cooldown_days === "number" ? st.nudge_cooldown_days : 30,
		};
	}

	// Client-side cadence FALLBACK (used only when the server didn't ship
	// `nudge_state.eligible`). Uses the knobs when present, else the defaults:
	// knob on ∧ 0 creds ∧ declines < max ∧ cooldown elapsed ∧ not opted out.
	function clientEligible(boot, now) {
		var knobs = nudgeKnobs(boot);
		var st = nudgeState(boot);
		var count = typeof boot.credential_count === "number" ? boot.credential_count : 0;
		if (!knobs.nudgeEnabled) return false;
		if (count > 0) return false;
		if (st.optOut) return false;
		if (st.declines >= knobs.maxPrompts) return false;
		if (!cooldownElapsed(st.lastShown, knobs.cooldownDays, now)) return false;
		return true;
	}

	// The AUTHORITATIVE visible-nudge cadence: the server computes it in
	// `boot.nudge_state.eligible` (counters are server-side, "never
	// client-side-only caps"). Trust it when present; fall back to clientEligible
	// only for a bootinfo that predates the flag.
	function serverEligible(boot, now) {
		var ns = boot && boot.nudge_state;
		if (ns && typeof ns.eligible === "boolean") return ns.eligible;
		return clientEligible(boot, now);
	}

	// The post-login enrollment-nudge decision. The server owns cadence
	// (`nudge_state.eligible`); the client only ANDs its capability checks. Returns
	// a verdict with a machine-readable `reason` for tests/telemetry.
	//   boot: frappe.boot.passkeys (see the build manifest for the exact contract)
	//   caps: client capability probe (supported / conditionalCreate)
	function nudgeDecision(boot, caps, now) {
		boot = boot || {};
		caps = caps || {};
		var supported = caps.supported !== false; // unknown counts as supported
		var eligible = serverEligible(boot, now);

		var out = { showNudge: false, allowConditionalCreate: false, reason: "", eligible: eligible };
		if (!eligible) out.reason = "server_ineligible";
		else if (!supported) out.reason = "unsupported";
		else { out.showNudge = true; out.reason = "eligible"; }

		// Conditional create (silent upgrade): its own knob
		// (`boot.conditional_create`, the server flag — fail-safe OFF when absent),
		// the client capability, AND a PASSWORD-seeded fresh-login window
		// (post_login_method === "password") — a raw session-age check cannot tell a
		// password login from an email-link one. Rides the server cadence
		// (`eligible` already encodes 0 credentials + the nudge knob).
		out.allowConditionalCreate =
			eligible &&
			caps.conditionalCreate === true &&
			boot.post_login_method === "password" &&
			boot.conditional_create === true;

		return out;
	}

	// The post-login ENFORCEMENT decision — the §capability hinge. The server owns the
	// verdict (`boot.enforcement`: scope / date / grace); the client's only job is to
	// honor DEVICE CAPABILITY, which the server cannot know. Returns:
	//   show        — surface an interstitial at all
	//   variant     — "enforce" (the blocking/skippable enrollment gate) or "nudge"
	//                 (a genuinely-incapable device under Degrade — never a dead-end)
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
			// Degrade to a non-blocking nudge variant (the default escape hatch).
			out.show = true;
			out.variant = "nudge";
			out.blocking = false;
			out.reason = "incapable_degrade";
		}
		return out;
	}

	// Post-hybrid upsell: after a hybrid (QR) assertion with local isUVPAA
	// the login bundle set UPSELL_FLAG_KEY. Offer "add a passkey to this device",
	// **cadence-capped identically to the nudge but WITHOUT the 0-credentials gate**
	// (the user just signed in, so they already hold ≥1 credential). Prefer a
	// server `upsell_eligible` flag; else a conservative client cadence over the
	// cadence signals present in bootinfo (declines / opt_out), default cap.
	// `storageGet(key)` reads localStorage (injected so the logic stays browser-free).
	function upsellDecision(boot, caps, storageGet, now) {
		boot = boot || {};
		caps = caps || {};
		var flagged = false;
		try {
			flagged = typeof storageGet === "function" && storageGet(UPSELL_FLAG_KEY) === "1";
		} catch (e) {
			flagged = false;
		}
		var st = nudgeState(boot);
		var knobs = nudgeKnobs(boot);
		var supported = caps.supported !== false;
		var uvpaaOk = caps.uvpaa !== false; // unknown ⇒ still offer (local sheet decides)
		var cadence = typeof boot.upsell_eligible === "boolean"
			? boot.upsell_eligible
			: (!st.optOut && st.declines < knobs.maxPrompts && cooldownElapsed(st.lastShown, knobs.cooldownDays, now));

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

	// ------------------------------------------------- last-method delete guard
	// Client mirror of the census guard (advisory — delete_credential enforces
	// it server-side and is authoritative). Refuse dropping the final enabled
	// credential of a passkey-only user (or under site disable_user_pass_login).
	//   ctx: { enabledCount, passkeyOnly, disablePassLogin }
	function deleteGuard(cred, ctx) {
		cred = cred || {};
		ctx = ctx || {};
		if (!isTruthy(cred.enabled)) return { blocked: false, reason: "soft_disabled" };
		if ((ctx.enabledCount || 0) > 1) return { blocked: false, reason: "another_survives" };
		if (isTruthy(ctx.passkeyOnly) || isTruthy(ctx.disablePassLogin)) {
			return { blocked: true, reason: "last_method", messageKey: COPY.lastMethodBlocked };
		}
		return { blocked: false, reason: "ok" };
	}

	// ---------------------------------------------------- settings banners
	// A pure decision matrix: given the Passkey Settings values + optional server
	// context, return the banners to paint. Each is {level, key, args}. The DOM
	// layer maps `key` (a COPY.* string) through __(). Banners that need cross-flag
	// server data (core enable_two_factor_auth / disable_user_pass_login / the
	// flagged-user count) are emitted ONLY when that data is supplied in `ctx`.
	//   doc: { login_with_passkey, passkey_as_second_factor, passkey_notify_on_change,
	//          passkey_rp_id, passkey_origins }
	//   ctx: { currentHost, resolvedRpId, resolvedOrigins, coreTwoFactor,
	//          disablePassLogin, passkeyOnlyUserCount }
	function settingsBanners(doc, ctx) {
		doc = doc || {};
		ctx = ctx || {};
		var banners = [];
		var firstFactor = isTruthy(doc.login_with_passkey);
		var secondFactor = isTruthy(doc.passkey_as_second_factor);
		var anyMode = firstFactor || secondFactor;

		// Always warn about the RP-ID one-way door (loud warning).
		banners.push({ level: "warning", key: COPY.rpIdOneWayDoor });

		// No RP ID resolves while a mode is being enabled — this is exactly the
		// save-blocking condition the server throws on (_validate_enablement), surfaced
		// INLINE before save with the two concrete fixes. `resolvedRpId` is now
		// server-truth (explicit field, else the server host_name resolution — never
		// the browser host), so a blank value here means Save WILL fail.
		if (anyMode && !ctx.resolvedRpId) {
			banners.push({ level: "error", key: COPY.rpIdUnresolved, args: [ctx.currentHost || ""] });
		}

		// Host mismatch — fail-closed must be diagnosable. Client-computable
		// from the resolved origins vs the current host. Only meaningful once an RP ID
		// actually resolves (otherwise rpIdUnresolved above is the real story).
		if (
			ctx.resolvedRpId &&
			ctx.currentHost &&
			Array.isArray(ctx.resolvedOrigins) &&
			ctx.resolvedOrigins.length &&
			!originsIncludeHost(ctx.resolvedOrigins, ctx.currentHost)
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
			// Self-lockout: enforcing everyone without System Manager exempt.
			var exempt = roleNames(doc.passkey_enforce_exempt_roles);
			if (doc.passkey_enforce_scope !== "Selected Roles" && exempt.indexOf("System Manager") === -1) {
				banners.push({ level: "warning", key: COPY.enforceSelfLockout });
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

	// Client mirror of server policy.resolve_origins: the implicit
	// `https://<rp_id>` origin is ALWAYS present, then each non-empty
	// `passkey_origins` line (exact-string, dedup, order preserved). The settings
	// form must derive origins THIS way — omitting the implicit origin for a
	// non-empty list makes a healthy site show a false host-mismatch banner, since
	// the server never actually drops it.
	function deriveOrigins(raw, rpId) {
		var origins = rpId ? ["https://" + rpId] : [];
		String(raw || "").split(/\r?\n/).forEach(function (line) {
			line = line.trim();
			if (line && origins.indexOf(line) === -1) origins.push(line);
		});
		return origins;
	}

	// Exact-host membership for an origins allowlist (host compare, scheme-tolerant).
	function originsIncludeHost(origins, host) {
		host = String(host || "").toLowerCase();
		for (var i = 0; i < origins.length; i++) {
			var h = originHost(origins[i]);
			if (h && h === host) return true;
		}
		return false;
	}
	function originHost(origin) {
		var s = String(origin || "").trim().toLowerCase();
		s = s.replace(/^https?:\/\//, "");
		s = s.replace(/\/.*$/, "");
		return s || null;
	}

	// ---------------------------------------------------- security posture panel
	// Pure renderer for the admin "Security posture" panel. The SERVER
	// (posture.build_posture) ships the verdict + already-translated rows; this only
	// ORDERS them for the attention hierarchy and shapes a view-model — NO copy lives
	// here (the reveal-vs-vague split is decided server-side, on the SM-only surface).
	// Order: severity high→medium→low→info, and the detectability disclaimer
	// (detectable === false) always sorts LAST regardless of its severity.
	var POSTURE_SEVERITY_RANK = { high: 0, medium: 1, low: 2, info: 3 };

	function posturePanel(response) {
		response = response || {};
		var verdict = response.verdict || {};
		var rows = Array.isArray(response.rows) ? response.rows.slice() : [];
		// Stable sort (V8): the disclaimer sinks last, then by severity; server order
		// is preserved within a bucket.
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
		// F3: an EMPTY ids array is valid and INTENTIONAL — after a genuine last-passkey
		// delete the provider is meant to hide ALL of the user's passkeys. We reject only a
		// NON-array (nothing to signal); [] passes through on purpose. The desk/portal caller
		// fires this only behind a successful server read, so a failed list never sends [].
		return { userHandle: userHandle, allAcceptedCredentialIds: ids.slice() };
	}

	// Shape a signalCurrentUserDetails payload (F2) from a get_signal_data response or a
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

	return {
		// wire seam
		MANAGE_METHODS: MANAGE_METHODS,
		MANAGE_ACTION: MANAGE_ACTION,
		PASSKEY_ONLY_ACTION: PASSKEY_ONLY_ACTION,
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
		cooldownElapsed: cooldownElapsed,
		nudgeState: nudgeState,
		nudgeKnobs: nudgeKnobs,
		clientEligible: clientEligible,
		serverEligible: serverEligible,
		nudgeDecision: nudgeDecision,
		enforcementDecision: enforcementDecision,
		upsellDecision: upsellDecision,
		deleteGuard: deleteGuard,
		settingsBanners: settingsBanners,
		roleNames: roleNames,
		deriveOrigins: deriveOrigins,
		originsIncludeHost: originsIncludeHost,
		originHost: originHost,
		posturePanel: posturePanel,
		signalPayload: signalPayload,
		currentUserDetailsPayload: currentUserDetailsPayload,
	};
});
