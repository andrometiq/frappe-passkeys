// passkey_manage_common.js — shared PURE logic for the §8 credential-management
// surfaces + §8.4 enrollment nudges + §9.4 settings UX. Destination on core merge:
// frappe/public/js/frappe/passkey/ (frappe.ui.passkey.*).
//
// Like passkey_common.js this module is deliberately framework-light and
// side-effect-free at load time so its pure logic (card view-models, provider
// resolution, the nudge cadence decision, the post-hybrid upsell gate, the §9.4
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
// app_include_js/web_include_js entry AFTER passkey_common.js).
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
	// nudge rows are REQUESTED endpoints (§3.0 rows 12/13) — see the build manifest.
	var MANAGE_METHODS = {
		list: "passkeys.api.credentials.list_credentials",
		rename: "passkeys.api.credentials.rename_credential",
		del: "passkeys.api.credentials.delete_credential",
		setPasskeyOnly: "passkeys.api.credentials.set_passkey_only_login",
		beginRegistration: "passkeys.api.registration.begin_registration",
		verifyRegistration: "passkeys.api.registration.verify_registration",
		// §3.0 rows 12/13 — the server phase built these on passkey.py.
		recordNudge: "passkeys.passkey.record_nudge",
		getSignalData: "passkeys.passkey.get_signal_data",
	};

	// The confirm-ceremony action that sudo-gates the app's own management
	// surface (§7.1/§7.4): a live `passkeys.manage` window OR a fresh passkey
	// confirmation satisfies delete / explicit registration.
	var MANAGE_ACTION = "passkeys.manage";

	// The dedicated per-user passkey-grant action for the passkey-only switch
	// (§9.3 F19). set_passkey_only_login accepts a passkey grant ONLY.
	var PASSKEY_ONLY_ACTION = "passkeys.set_passkey_only_login";

	// record_nudge event enum (§3.0 row 13).
	var NUDGE_EVENTS = { SHOWN: "shown", DECLINED: "declined", OPT_OUT: "opt_out" };

	// localStorage key the login bundle sets after a hybrid (QR) assertion with
	// local isUVPAA (§5.2 step 8 / §8.4 post-hybrid upsell).
	var UPSELL_FLAG_KEY = "passkey_upsell_add_local";

	var ZERO_AAGUID = "00000000-0000-0000-0000-000000000000";

	// ===================================================== translatable copy keys
	// English source strings (the DOM layer wraps each with __()). Grouped so the
	// server phase can mirror them into translations/{lang}.csv (§5.6). Logic here
	// never bakes a language in — it returns keys/args, the renderer translates.
	var COPY = {
		// cards / empty state (§8.2)
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
		// friendly ceremony errors (§8.2)
		alreadyRegistered: "This device already has a passkey for this account.",
		addExpired: "That took too long — please try again.",
		addFailed: "Couldn't add a passkey — please try again.",
		// last-method guard (§8.3)
		lastMethodBlocked:
			"This is your only passkey and passwordless login is on for your account — " +
			"add another passkey (or turn off passkey-only login) before removing it.",
		// nudge (§8.4)
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
		// passkey-only switch (§9.3)
		passkeyOnlyLabel: "Passwordless login only",
		passkeyOnlyHelp:
			"Turn off password sign-in for your account. Needs at least two passkeys so a " +
			"lost device never locks you out.",
		// settings banners (§9.4) — keyed; args filled by the matrix
		rpIdOneWayDoor:
			"Changing the RP ID invalidates every existing passkey. This cannot be undone.",
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
	// Card provider name (§8.2). Preference order:
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

	// Synced (multi-device / backup_state) vs Device-bound badge (§2.1/§8.2).
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

	// Accessible name for an icon-only card action (§5.5 "Rename passkey ⟨label⟩").
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

	// ------------------------------------------------------- nudge cadence (§8.4)
	// Whether the cooldown window has elapsed since the last nudge. `cooldownDays`
	// is the `passkey_nudge_cooldown_days` knob (default 30 — F3-8). Never shown ⇒
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
	// `nudge_state.eligible`). Uses the knobs when present, else the §9.1 defaults
	// (F3-8): knob on ∧ 0 creds ∧ declines < max ∧ cooldown elapsed ∧ not opted out.
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
	// `boot.nudge_state.eligible` (§8.4 — counters are server-side, "never
	// client-side-only caps"). Trust it when present; fall back to clientEligible
	// only for a bootinfo that predates the flag.
	function serverEligible(boot, now) {
		var ns = boot && boot.nudge_state;
		if (ns && typeof ns.eligible === "boolean") return ns.eligible;
		return clientEligible(boot, now);
	}

	// The post-login enrollment-nudge decision (§8.4). The server owns cadence
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

		// Conditional create (silent upgrade, §8.4): its own knob
		// (`boot.conditional_create`, the server flag — fail-safe OFF when absent),
		// the client capability, AND a PASSWORD-seeded fresh-login window
		// (post_login_method === "password") — a raw session-age check cannot tell a
		// password login from an email-link one (§7.1). Rides the server cadence
		// (`eligible` already encodes 0 credentials + the nudge knob).
		out.allowConditionalCreate =
			eligible &&
			caps.conditionalCreate === true &&
			boot.post_login_method === "password" &&
			boot.conditional_create === true;

		return out;
	}

	// Post-hybrid upsell (§8.4): after a hybrid (QR) assertion with local isUVPAA
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
	// Client mirror of the §8.3 census guard (advisory — delete_credential enforces
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

	// ---------------------------------------------------- settings banners (§9.4)
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

		// Always warn about the RP-ID one-way door (§9.1 loud warning).
		banners.push({ level: "warning", key: COPY.rpIdOneWayDoor });

		// Host mismatch — fail-closed must be diagnosable (§9.2). Client-computable
		// from the resolved origins vs the current host.
		if (
			ctx.currentHost &&
			Array.isArray(ctx.resolvedOrigins) &&
			ctx.resolvedOrigins.length &&
			!originsIncludeHost(ctx.resolvedOrigins, ctx.currentHost)
		) {
			banners.push({ level: "error", key: COPY.hostMismatch, args: [ctx.resolvedRpId || ""] });
		}

		// §2.3 validator: 2FA needs core two-factor ON (row 2). Client pre-warn.
		if (secondFactor && ctx.coreTwoFactor !== undefined && !isTruthy(ctx.coreTwoFactor)) {
			banners.push({ level: "error", key: COPY.twofaRequiresCore });
		}

		// §9.4 row 6 warning: dead 2FA combo under site disable_user_pass_login.
		if (secondFactor && ctx.disablePassLogin !== undefined && isTruthy(ctx.disablePassLogin)) {
			banners.push({ level: "warning", key: COPY.deadTwofaCombo });
		}

		// §9.4 row 14 warning: notifications off weakens the hijack safeguard.
		if (anyMode && doc.passkey_notify_on_change !== undefined && !isTruthy(doc.passkey_notify_on_change)) {
			banners.push({ level: "warning", key: COPY.notifyOffWeakens });
		}

		// §9.4 rows 5/15 generalized guard pre-warn: no passkey-capable mode left
		// while passkey-only users exist (server REFUSES the save — this is a heads-up).
		if (!anyMode && (ctx.passkeyOnlyUserCount || 0) > 0) {
			banners.push({
				level: "error",
				key: COPY.strandsPasskeyOnlyUsers,
				args: [ctx.passkeyOnlyUserCount],
			});
		}

		// §9.4 row 4 "pause": both modes off is legal but the UI removes itself.
		if (!anyMode) {
			banners.push({ level: "info", key: COPY.allModesOff });
		}

		return banners;
	}

	// Client mirror of server policy.resolve_origins (§9.2): the implicit
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

	// ---------------------------------------------------------- signal payloads
	// Shape a signalAllAcceptedCredentials payload from a verify_registration
	// signal block or a get_signal_data response (§8.3 / §3.2). Returns null when
	// there is nothing to signal (caller then no-ops — fire-and-forget).
	function signalPayload(data) {
		var s = data && (data.signal || data);
		if (!s) return null;
		var userHandle = s.user_handle || s.userHandle || null;
		var ids = s.credential_ids || s.credentialIds || null;
		if (!userHandle || !Array.isArray(ids)) return null;
		return { userHandle: userHandle, allAcceptedCredentialIds: ids.slice() };
	}

	return {
		// wire seam
		MANAGE_METHODS: MANAGE_METHODS,
		MANAGE_ACTION: MANAGE_ACTION,
		PASSKEY_ONLY_ACTION: PASSKEY_ONLY_ACTION,
		NUDGE_EVENTS: NUDGE_EVENTS,
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
		upsellDecision: upsellDecision,
		deleteGuard: deleteGuard,
		settingsBanners: settingsBanners,
		deriveOrigins: deriveOrigins,
		originsIncludeHost: originsIncludeHost,
		originHost: originHost,
		signalPayload: signalPayload,
	};
});
