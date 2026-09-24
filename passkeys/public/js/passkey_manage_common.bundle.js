// Credential management, enrollment nudges and the settings UX: the decisions, and the
// card DOM the desk and portal share. Side-effect-free at load. Published as
// `frappe.passkeys_manage_common` (CommonJS for node tests); loads after passkey_common.
// eslint-env browser, node
(function (root, factory) {
	"use strict";
	var api = factory();
	if (typeof module === "object" && module.exports) module.exports = api;
	if (typeof window !== "undefined") {
		window.frappe = window.frappe || {};
		window.frappe.passkeys_manage_common = api;
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
		getUserEnforcementAdmin: "passkeys.enforcement_admin.get_user_enforcement_admin",
		setUserExemption: "passkeys.enforcement_admin.set_user_exemption",
		resetEnforcementGrace: "passkeys.enforcement_admin.reset_enforcement_grace",
	};

	// The confirmation action that sudo-gates delete and explicit registration.
	var MANAGE_ACTION = "passkeys.manage";

	var NUDGE_EVENTS = { SHOWN: "shown", DECLINED: "declined", OPT_OUT: "opt_out" };

	// DEFER spends one grace login; INCAPABLE reports a device that cannot create a passkey.
	var ENFORCE_EVENTS = { DEFER: "defer", INCAPABLE: "incapable" };

	// Set by the login bundle after a cross-device (QR) sign-in.
	var UPSELL_FLAG_KEY = "passkey_upsell_add_local";

	var ZERO_AAGUID = "00000000-0000-0000-0000-000000000000";

	// English source strings; the renderer translates them.
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
		// enforcement interstitial (guilt-free copy, per the FIDO no-dark-patterns guidance)
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
		enforceNoMode:
			"Enrollment enforcement has no effect while both passkey login modes are off. Enable a " +
			"passkey login mode for the policy to apply.",
		enforcePrivilegedOutside:
			"Privileged users (System Manager) are outside passkey enforcement. Administrators are " +
			"the accounts attackers target first — industry practice enforces them first.",
		enforceEmptyRoles:
			"Require a passkey from is 'Selected roles' but no roles are listed, so it applies " +
			"to nobody. Add the roles to require, or switch to 'All users'.",
		enforceBlockIncapable:
			"Incapable Device Policy is 'Block + Notify Admin': users on devices that cannot create " +
			"a passkey (and cannot use a phone) will be blocked rather than nudged.",
		enforcePreview:
			"This policy would require a passkey from {0} in-scope user(s) who do not have one yet.",
	};

	// {0}/{1} placeholders; the caller translates first.
	function format(str, args) {
		if (!args || !args.length) return str;
		return String(str).replace(/\{(\d+)\}/g, function (m, i) {
			var v = args[Number(i)];
			return v === undefined || v === null ? "" : String(v);
		});
	}

	// ---------------------------------------------------------- provider lookup
	// Provider name: the server's, else the AAGUID map's, else null. Safari sends a zero AAGUID.
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

	// Per-credential card view-model; values stay raw (the DOM layer formats them).
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

	// The post-login enforcement decision. The server owns the verdict (boot.enforcement);
	// the client adds only device capability. variant "enforce" is the enrollment gate,
	// "nudge" an incapable device under Degrade; notifyAdmin records the incapable event.
	function enforcementDecision(boot, caps) {
		boot = boot || {};
		caps = caps || {};
		var enf = boot.enforcement || {};
		var out = {
			show: false, blocking: false, variant: "",
			notifyAdmin: false, graceRemaining: 0, reason: "",
		};
		// Off / nudge / before the date / out of scope: the nudge path owns it.
		if (enf.effective !== "enforce" || !enf.in_scope) { out.reason = "not_enforcing"; return out; }
		var count = typeof boot.credential_count === "number" ? boot.credential_count : 0;
		if (count > 0) { out.reason = "satisfied"; return out; }

		out.graceRemaining = typeof enf.grace_remaining === "number" ? enf.grace_remaining : 0;
		var supported = caps.supported !== false; // unknown counts as capable
		var uvpaaOk = caps.uvpaa !== false; // unknown counts as capable
		var hybridOk = caps.hybrid !== false; // unknown counts as capable
		// Phone/QR enrollment is always offered; a hybrid transport counts as capable.
		var canEnroll = supported && (uvpaaOk || hybridOk);

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
	// The User-form recovery controls show only while the site requires a passkey from someone.
	function shouldShowEnforcementAdmin(boot) {
		return !!(boot && boot.enforcement && boot.enforcement.enforcing);
	}

	// View-model for get_user_enforcement_admin.
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
			exemptButtonKey: exempt ? "enforceAdminUnexempt" : "enforceAdminExempt",
			exemptButtonPrimary: !exempt,
			nextExemptValue: !exempt,
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
	// {level, key, args} banners for the Passkey Settings form. Those that need server
	// context appear only when `ctx` carries it (see passkey_settings.js buildContext).
	function settingsBanners(doc, ctx) {
		doc = doc || {};
		ctx = ctx || {};
		var banners = [];
		var firstFactor = isTruthy(doc.login_with_passkey);
		var secondFactor = isTruthy(doc.passkey_as_second_factor);
		var anyMode = firstFactor || secondFactor;

		// Save will fail without an RP ID, so say how to fix it now.
		if (anyMode && !ctx.resolvedRpId) {
			banners.push({ level: "error", key: COPY.rpIdUnresolved, args: [ctx.currentHost || ""] });
		}

		// This page's origin is not trusted, so ceremonies here will fail.
		if (
			ctx.resolvedRpId &&
			ctx.currentOrigin &&
			Array.isArray(ctx.resolvedOrigins) &&
			ctx.resolvedOrigins.length &&
			!originsIncludeOrigin(ctx.resolvedOrigins, ctx.currentOrigin)
		) {
			banners.push({ level: "error", key: COPY.hostMismatch, args: [ctx.resolvedRpId || ""] });
		}

		if (secondFactor && ctx.coreTwoFactor !== undefined && !isTruthy(ctx.coreTwoFactor)) {
			banners.push({ level: "error", key: COPY.twofaRequiresCore });
		}

		if (secondFactor && ctx.disablePassLogin !== undefined && isTruthy(ctx.disablePassLogin)) {
			banners.push({ level: "warning", key: COPY.deadTwofaCombo });
		}

		if (anyMode && doc.passkey_notify_on_change !== undefined && !isTruthy(doc.passkey_notify_on_change)) {
			banners.push({ level: "warning", key: COPY.notifyOffWeakens });
		}

		// The server refuses this save; warn before it.
		if (!anyMode && (ctx.passkeyOnlyUserCount || 0) > 0) {
			banners.push({
				level: "error",
				key: COPY.strandsPasskeyOnlyUsers,
				args: [ctx.passkeyOnlyUserCount],
			});
		}

		var scope = doc.passkey_enforce_scope || "No one";
		var privileged = isTruthy(doc.passkey_enforce_privileged_always);
		var enforcing = scope !== "No one" || privileged;

		if (enforcing) {
			if (!anyMode) banners.push({ level: "warning", key: COPY.enforceNoMode });
			if (scope === "Selected roles" && !privileged) {
				banners.push({ level: "warning", key: COPY.enforcePrivilegedOutside });
			}
			if (scope === "Selected roles" && !roleNames(doc.passkey_enforce_roles).length) {
				banners.push({ level: "warning", key: COPY.enforceEmptyRoles });
			}
			if (doc.passkey_enforce_incapable === "Block + Notify Admin") {
				banners.push({ level: "warning", key: COPY.enforceBlockIncapable });
			}
			if (typeof ctx.wouldBeBlockedCount === "number") {
				banners.push({ level: "info", key: COPY.enforcePreview, args: [ctx.wouldBeBlockedCount] });
			}
		}

		if (!anyMode) {
			banners.push({ level: "info", key: COPY.allModesOff });
		}

		return banners;
	}

	// A Table MultiSelect value (child rows or strings) as role names.
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

	// Turning passkey-only on needs two enabled credentials; turning it off is always allowed.
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

	// The grace count changes after a successful defer, so user + remaining count keys one
	// defer per verdict across retries and reloads.
	function enforcementDeferKey(user, enforcement) {
		enforcement = enforcement || {};
		return "passkey_enforcement_defer:" + encodeURIComponent(String(user || "current")) +
			":" + encodeURIComponent(String(enforcement.effective || "enforce")) +
			":" + cint(enforcement.graceRemaining !== undefined
				? enforcement.graceRemaining : enforcement.grace_remaining);
	}

	// Run one asynchronous event per key, remembered in sessionStorage (or memory where
	// storage is unavailable). A failure clears the key so it can be retried.
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

	// Exact scheme, host and port, as the server matches clientDataJSON.origin.
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
	// The server's posture rows, high→info, with the undetectable disclaimer always last.
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
	// signalAllAcceptedCredentials from a verify_registration signal block or get_signal_data;
	// null when there is nothing to signal. An empty list after the last delete is intended.
	function signalPayload(data) {
		var s = data && (data.signal || data);
		if (!s) return null;
		var userHandle = s.user_handle || s.userHandle || null;
		var ids = s.credential_ids || s.credentialIds || null;
		if (!userHandle || !Array.isArray(ids)) return null;
		return { userHandle: userHandle, allAcceptedCredentialIds: ids.slice() };
	}

	// signalCurrentUserDetails needs both names; mirror one into the other so the provider's
	// account label is never blanked.
	function currentUserDetailsPayload(data) {
		var s = data && (data.signal || data);
		if (!s) return null;
		var userHandle = s.user_handle || s.userHandle || null;
		var name = s.name || null;
		var displayName = s.display_name || s.displayName || null;
		if (!userHandle || (!name && !displayName)) return null;
		return { userHandle: userHandle, name: name || displayName, displayName: displayName || name };
	}

	// Fire both Signal API updates, best-effort: never awaited, failures swallowed (Firefox has
	// none; Safari 26 can leave the promise unsettled).
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

	// ================================================= shared management DOM
	// The desk and portal cards follow one markup contract (docs/custom-ui.md). DOM is built
	// only when these are called.
	function common() { return window.frappe.passkeys_common; }

	function el(tag, className, text) {
		var node = document.createElement(tag);
		if (className) node.className = className;
		if (text != null) node.textContent = text;
		return node;
	}

	// kind: "primary" | "default" (Frappe secondary).
	function button(kind, label, onClick) {
		var node = el("button", "btn btn-" + kind + " btn-sm passkey-btn", label);
		node.type = "button";
		node.addEventListener("click", onClick);
		return node;
	}

	function iconButton(className, iconName, name, onClick) {
		var node = el("button", "btn btn-xs btn-default passkey-icon-btn " + className);
		node.type = "button";
		node.setAttribute("aria-label", name); // the icon-only action's accessible name
		node.setAttribute("title", name);
		var glyph = el("span", "passkey-icon");
		glyph.setAttribute("aria-hidden", "true");
		glyph.innerHTML = common().iconSvg(iconName, "icon icon-sm");
		node.appendChild(glyph);
		node.addEventListener("click", onClick);
		return node;
	}

	function formatDate(value) {
		if (!value) return "—";
		try {
			return window.frappe.datetime.str_to_user(value);
		} catch (e) {
			return String(value); // portal pages may lack frappe.datetime or its boot defaults
		}
	}

	// The <ul> of cards. actionsFor(vm) returns {onRename, onDelete}, or null for read-only.
	function cardList(creds, aaguidMap, actionsFor) {
		var t = common().t;
		var list = el("ul", "passkey-card-list");
		list.setAttribute("role", "list");
		creds.forEach(function (cred) {
			var vm = credentialViewModel(cred, { aaguidMap: aaguidMap, translate: t });
			list.appendChild(cardElement(vm, actionsFor(vm), t));
		});
		return list;
	}

	function cardElement(vm, actions, t) {
		var card = el("li", "passkey-card" + (vm.enabled ? "" : " passkey-card-disabled"));
		card.setAttribute("data-name", vm.name);
		var glyph = el("span", "passkey-card-glyph");
		glyph.setAttribute("aria-hidden", "true");
		glyph.innerHTML = common().iconSvg("key", "icon");
		card.appendChild(glyph);

		var main = el("div", "passkey-card-main");
		var labelRow = el("div", "passkey-card-labelrow");
		var label = el("span", "passkey-card-label", vm.label);
		label.setAttribute("title", vm.label);
		labelRow.appendChild(label);
		var badge = el("span", "passkey-badge passkey-badge-" + (vm.badge.synced ? "synced" : "device"), t(vm.badge.key));
		badge.setAttribute("title", t(vm.badge.hintKey));
		labelRow.appendChild(badge);
		if (!vm.enabled) labelRow.appendChild(el("span", "passkey-badge passkey-badge-disabled", t(COPY.disabledBadge)));
		main.appendChild(labelRow);

		var meta = el("div", "passkey-card-meta");
		meta.appendChild(el("span", "passkey-card-provider", vm.hasProvider ? vm.providerName : t(vm.unknownProviderKey)));
		meta.appendChild(el("span", "passkey-card-created", t(COPY.createdLabel) + ": " + formatDate(vm.created)));
		meta.appendChild(el("span", "passkey-card-lastused",
			vm.lastUsed ? t(COPY.lastUsedLabel) + ": " + formatDate(vm.lastUsed) : t(COPY.lastUsedNever)));
		main.appendChild(meta);
		if (vm.flagged) {
			var flagged = el("div", "passkey-card-flagged", t(COPY.flaggedBanner));
			flagged.setAttribute("role", "alert");
			main.appendChild(flagged);
		}
		card.appendChild(main);

		if (actions) {
			var row = el("div", "passkey-card-actions");
			row.appendChild(iconButton("passkey-rename", "pencil", vm.a11y.rename, actions.onRename));
			row.appendChild(iconButton("passkey-delete", "trash", vm.a11y.del, actions.onDelete));
			card.appendChild(row);
		}
		return card;
	}

	function emptyState(onAdd) {
		var t = common().t;
		var wrap = el("div", "passkey-empty");
		wrap.appendChild(el("h4", "passkey-empty-title", t(COPY.emptyTitle)));
		wrap.appendChild(el("p", "passkey-empty-body", t(COPY.emptyBody)));
		var cta = button("primary", t(COPY.addButton), onAdd);
		cta.className += " passkey-empty-cta";
		wrap.appendChild(cta);
		return wrap;
	}

	// The passwordless-login switch, from a list_credentials payload. It never flips on its
	// own: it snaps back and asks onRequest(desired); the change shows once the sudo-gated
	// call succeeds and the list is re-rendered.
	function passkeyOnlyRow(payload, onRequest) {
		var t = common().t;
		var enabledCount = payload.credentials.filter(function (c) { return credentialViewModel(c).enabled; }).length;
		var current = !!payload.passkey_only_login;
		var availability = passkeyOnlyAvailability(enabledCount, current);
		var row = el("div", "passkey-only-row");
		var main = el("div", "passkey-only-main");
		main.appendChild(el("div", "passkey-only-label", t(COPY.passkeyOnlyLabel)));
		main.appendChild(el("div", "passkey-only-help", t(COPY[availability.helpKey])));
		row.appendChild(main);
		var toggle = el("input", "passkey-only-toggle");
		toggle.type = "checkbox";
		toggle.checked = current;
		toggle.setAttribute("role", "switch");
		toggle.setAttribute("aria-checked", current ? "true" : "false");
		toggle.setAttribute("aria-label", t(COPY.passkeyOnlyLabel));
		if (availability.disabled) {
			toggle.disabled = true;
			toggle.setAttribute("title", t(COPY.passkeyOnlyNeedsTwo));
		}
		toggle.addEventListener("change", function () {
			var desired = toggle.checked;
			toggle.checked = current;
			if (desired !== current) onRequest(desired);
		});
		row.appendChild(toggle);
		return row;
	}

	// The optional provider-name snapshot; {} when absent.
	var aaguidMapPromise = null;
	function loadAaguidMap() {
		if (!aaguidMapPromise) {
			aaguidMapPromise = fetch("/assets/passkeys/aaguid-map.json", { credentials: "same-origin" })
				.then(function (r) { return r.ok ? r.json() : {}; })
				.catch(function () { return {}; });
		}
		return aaguidMapPromise;
	}

	// Nudge and enforcement events for the desk and portal prompts.
	function createEnrollmentEvents(post) {
		var storage = null;
		try { storage = window.sessionStorage || null; } catch (e) { /* storage denied */ }
		var once = createSessionEventRecorder(storage);
		var incapableReported = false;
		function recordEnforcement(event) {
			return post(MANAGE_METHODS.recordEnforcement, { event: event });
		}
		return {
			// Resolves the response, or null on a transport failure (never rejects).
			recordNudge: function (event) {
				return post(MANAGE_METHODS.recordNudge, { event: event }).catch(function () { return null; });
			},
			// "Remind me later": one grace login per verdict, however often it is sent.
			recordEnforcementDefer: function (boot, decision) {
				var session = window.frappe.session;
				var verdict = Object.assign({}, boot && boot.enforcement, { graceRemaining: decision.graceRemaining });
				return once(enforcementDeferKey(session && session.user, verdict), function () {
					return recordEnforcement(ENFORCE_EVENTS.DEFER).then(function (res) {
						if (!res || !res.ok) throw new Error("record_enforcement_failed");
						return res;
					});
				}).catch(function () {});
			},
			// Once per page, so a repeated escape never sends the admin a second email.
			reportIncapableOnce: function () {
				if (incapableReported) return;
				incapableReported = true;
				recordEnforcement(ENFORCE_EVENTS.INCAPABLE).catch(function () {});
			},
		};
	}

	return {
		MANAGE_METHODS: MANAGE_METHODS,
		MANAGE_ACTION: MANAGE_ACTION,
		NUDGE_EVENTS: NUDGE_EVENTS,
		ENFORCE_EVENTS: ENFORCE_EVENTS,
		UPSELL_FLAG_KEY: UPSELL_FLAG_KEY,
		ZERO_AAGUID: ZERO_AAGUID,
		COPY: COPY,
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
		// shared management DOM
		el: el,
		button: button,
		cardList: cardList,
		emptyState: emptyState,
		passkeyOnlyRow: passkeyOnlyRow,
		loadAaguidMap: loadAaguidMap,
		createEnrollmentEvents: createEnrollmentEvents,
	};
});
