// passkey_manage_common.test.js — dependency-free unit harness for the PURE
// credential-management + nudge + settings logic in
// passkey_manage_common.bundle.js. Runs WITHOUT the bench and WITHOUT jsdom:
//   node --test passkeys/tests/js
//
// Covers: provider resolution (server-supplied / injected map / zero-AAGUID /
// unknown), Synced-vs-Device-bound badge, the card view-model + accessible names,
// the nudge cadence decision (every branch + knob-referenced caps), the
// conditional-create gate (password-seeded window only), the post-hybrid upsell
// gate, the last-method delete guard, the settings-banner matrix, origin/host
// membership, and signal-payload shaping.

const test = require("node:test");
const assert = require("node:assert");
const M = require("../../public/js/passkey_manage_common.bundle.js");

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse("2026-07-06T00:00:00Z");

// ---------------------------------------------------------- provider + badge

test("providerFor prefers server-supplied provider", () => {
	assert.strictEqual(M.providerFor({ provider: "iCloud Keychain", aaguid: "abc" }, {}), "iCloud Keychain");
});

test("providerFor falls back to the injected aaguid map (string or {name})", () => {
	const map = { "aa-bb": "Google Password Manager", "cc-dd": { name: "1Password" } };
	assert.strictEqual(M.providerFor({ aaguid: "AA-BB" }, map), "Google Password Manager");
	assert.strictEqual(M.providerFor({ aaguid: "cc-dd" }, map), "1Password");
});

test("providerFor: zero / empty / unmapped AAGUID is Unknown (null), never an error", () => {
	assert.strictEqual(M.providerFor({ aaguid: M.ZERO_AAGUID }, { anything: "x" }), null);
	assert.strictEqual(M.providerFor({ aaguid: "" }, {}), null);
	assert.strictEqual(M.providerFor({ aaguid: "not-in-map" }, { other: "x" }), null);
	assert.strictEqual(M.providerFor({}, null), null);
});

test("backupBadge: backup_state truthy => Synced, else Device-bound", () => {
	assert.deepStrictEqual(M.backupBadge({ backup_state: 1 }).synced, true);
	assert.strictEqual(M.backupBadge({ backup_state: 1 }).key, M.COPY.syncedBadge);
	assert.strictEqual(M.backupBadge({ backup_state: 0 }).synced, false);
	assert.strictEqual(M.backupBadge({ backup_state: 0 }).key, M.COPY.deviceBoundBadge);
	assert.strictEqual(M.backupBadge({}).synced, false);
});

// ------------------------------------------- vendored AAGUID snapshot
// The REAL release asset the bundles fetch from /assets/passkeys/aaguid-map.json
// (source + refresh: docs/aaguid-map.md). These pin its contract: lean flat map
// (no icon blobs), lowercase-UUID keys, a skipped _meta provenance block.

const VENDORED_MAP = require("../../public/aaguid-map.json");
const KNOWN_AAGUID = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"; // Google Password Manager

test("vendored aaguid-map.json: lean shape — lowercase UUID keys, non-empty string names", () => {
	const keys = Object.keys(VENDORED_MAP).filter((k) => k[0] !== "_");
	assert.ok(keys.length > 0, "snapshot must not be empty");
	const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
	for (const k of keys) {
		assert.match(k, uuid, "key must be a lowercase UUID: " + k);
		assert.strictEqual(typeof VENDORED_MAP[k], "string", "value must be a plain name (icons stripped)");
		assert.ok(VENDORED_MAP[k].trim().length, "name must be non-empty");
	}
	assert.ok(VENDORED_MAP._meta, "provenance _meta block present");
});

test("viewmodel resolves a provider from the vendored map; label falls back to it", () => {
	const vm = M.credentialViewModel({ name: "c1", aaguid: KNOWN_AAGUID }, { aaguidMap: VENDORED_MAP });
	assert.strictEqual(vm.providerName, "Google Password Manager");
	assert.strictEqual(vm.hasProvider, true);
	// no user label ⇒ the provider name IS the card label
	assert.strictEqual(vm.label, "Google Password Manager");
	// a server-supplied provider field still wins over the map (source of truth)
	const vm2 = M.credentialViewModel(
		{ name: "c2", provider: "Server Says", aaguid: KNOWN_AAGUID },
		{ aaguidMap: VENDORED_MAP }
	);
	assert.strictEqual(vm2.providerName, "Server Says");
});

test("viewmodel falls back cleanly on zero/unmapped AAGUID with the real map (_meta never leaks)", () => {
	const zero = M.credentialViewModel({ name: "z", aaguid: M.ZERO_AAGUID }, { aaguidMap: VENDORED_MAP });
	assert.strictEqual(zero.providerName, null);
	assert.strictEqual(zero.hasProvider, false);
	assert.strictEqual(zero.label, M.COPY.unknownProvider);
	// a hostile/broken aaguid value colliding with the provenance key stays Unknown
	const meta = M.credentialViewModel({ name: "m", aaguid: "_meta" }, { aaguidMap: VENDORED_MAP });
	assert.strictEqual(meta.providerName, null);
});

// ---------------------------------------------------------- view-model + a11y

test("accessibleActionName fills the label placeholder", () => {
	assert.strictEqual(M.accessibleActionName("rename", "My phone"), "Rename passkey My phone");
	assert.strictEqual(M.accessibleActionName("delete", "My phone"), "Delete passkey My phone");
});

test("credentialViewModel: label falls back to provider then Unknown provider", () => {
	const vm1 = M.credentialViewModel({ name: "c1", label: "Nick", aaguid: "x", backup_state: 1 }, {});
	assert.strictEqual(vm1.label, "Nick");
	assert.strictEqual(vm1.badge.synced, true);
	assert.strictEqual(vm1.a11y.rename, "Rename passkey Nick");
	assert.strictEqual(vm1.a11y.del, "Delete passkey Nick");

	const vm2 = M.credentialViewModel({ name: "c2", provider: "iCloud Keychain", aaguid: "y" }, {});
	assert.strictEqual(vm2.label, "iCloud Keychain");
	assert.strictEqual(vm2.hasProvider, true);

	const vm3 = M.credentialViewModel({ name: "c3", aaguid: M.ZERO_AAGUID }, {});
	assert.strictEqual(vm3.label, M.COPY.unknownProvider);
	assert.strictEqual(vm3.hasProvider, false);
});

test("credentialViewModel: flagged + disabled surfaces reason + enabled flag", () => {
	const vm = M.credentialViewModel(
		{ name: "c1", label: "X", enabled: 0, flagged: 1, flagged_reason: "sign_count_regression" },
		{}
	);
	assert.strictEqual(vm.enabled, false);
	assert.strictEqual(vm.flagged, true);
	assert.strictEqual(vm.flaggedReason, "sign_count_regression");
});

// ---------------------------------------------------------- cooldown

test("cooldownElapsed: never-shown / unparseable => elapsed; within window => not", () => {
	assert.strictEqual(M.cooldownElapsed(null, 30, NOW), true);
	assert.strictEqual(M.cooldownElapsed("not-a-date", 30, NOW), true);
	assert.strictEqual(M.cooldownElapsed(new Date(NOW - 10 * DAY).toISOString(), 30, NOW), false);
	assert.strictEqual(M.cooldownElapsed(new Date(NOW - 31 * DAY).toISOString(), 30, NOW), true);
});

// ---------------------------------------------------------- nudge decision

// The REAL server bootinfo carries `nudge_state.eligible` (authoritative cadence)
// and `conditional_create` — no client `settings` knob block. bootBase mirrors it;
// bootLegacy (no `eligible`) exercises the client-knob fallback.
function bootBase(over) {
	return deepAssign(
		{
			modes: { first_factor: true, second_factor: false },
			enabled: true,
			credential_count: 0,
			nudge_state: { declines: 0, last_shown: null, opt_out: 0, eligible: true },
			post_login_method: "password",
			conditional_create: true,
		},
		over || {}
	);
}
function bootLegacy(over) {
	return deepAssign(
		{
			credential_count: 0,
			nudge_state: { declines: 0, last_shown: null, opt_out: 0 }, // NO eligible
			post_login_method: "password",
			settings: { nudge_enabled: 1, conditional_create: 1, nudge_max_prompts: 3, nudge_cooldown_days: 30 },
		},
		over || {}
	);
}
function deepAssign(base, over) {
	const out = Object.assign({}, base, over);
	if (over.nudge_state) out.nudge_state = Object.assign({}, base.nudge_state, over.nudge_state);
	if (over.settings) out.settings = Object.assign({}, base.settings, over.settings);
	return out;
}

test("nudgeDecision: trusts the server nudge_state.eligible verdict", () => {
	assert.strictEqual(M.nudgeDecision(bootBase(), { supported: true }, NOW).showNudge, true);
	const off = M.nudgeDecision(bootBase({ nudge_state: { eligible: false } }), { supported: true }, NOW);
	assert.strictEqual(off.showNudge, false);
	assert.strictEqual(off.reason, "server_ineligible");
});

test("nudgeDecision: eligible but unsupported client => no nudge", () => {
	assert.strictEqual(M.nudgeDecision(bootBase(), { supported: false }, NOW).reason, "unsupported");
});

test("nudgeDecision: client-knob FALLBACK when the server omits eligible (F3-8)", () => {
	// happy fallback
	assert.strictEqual(M.nudgeDecision(bootLegacy(), { supported: true }, NOW).showNudge, true);
	// knob off / already enrolled / opted out / max / cooldown all => server_ineligible
	assert.strictEqual(M.nudgeDecision(bootLegacy({ settings: { nudge_enabled: 0 } }), { supported: true }, NOW).showNudge, false);
	assert.strictEqual(M.nudgeDecision(bootLegacy({ credential_count: 2 }), { supported: true }, NOW).showNudge, false);
	assert.strictEqual(M.nudgeDecision(bootLegacy({ nudge_state: { opt_out: 1 } }), { supported: true }, NOW).showNudge, false);
	assert.strictEqual(M.nudgeDecision(bootLegacy({ nudge_state: { declines: 3 } }), { supported: true }, NOW).showNudge, false);
	assert.strictEqual(
		M.nudgeDecision(bootLegacy({ nudge_state: { last_shown: new Date(NOW - 5 * DAY).toISOString() } }), { supported: true }, NOW).showNudge,
		false
	);
	// custom max_prompts honoured (not hardcoded): 4 declines under a max of 5 still shows
	assert.strictEqual(
		M.nudgeDecision(bootLegacy({ settings: { nudge_max_prompts: 5 }, nudge_state: { declines: 4 } }), { supported: true }, NOW).showNudge,
		true
	);
});

test("nudgeDecision: conditional create gated on server eligible ∧ knob ∧ caps ∧ password window", () => {
	const caps = { supported: true, conditionalCreate: true };
	assert.strictEqual(M.nudgeDecision(bootBase(), caps, NOW).allowConditionalCreate, true);
	// email-link / weak login: window not password-seeded
	assert.strictEqual(M.nudgeDecision(bootBase({ post_login_method: "weak" }), caps, NOW).allowConditionalCreate, false);
	// no client capability => no silent create (Firefox story)
	assert.strictEqual(M.nudgeDecision(bootBase(), { supported: true, conditionalCreate: false }, NOW).allowConditionalCreate, false);
	// conditional-create knob off (server flag) => no silent create
	assert.strictEqual(M.nudgeDecision(bootBase({ conditional_create: false }), caps, NOW).allowConditionalCreate, false);
	// knob absent (fail-safe OFF)
	assert.strictEqual(M.nudgeDecision(bootBase({ conditional_create: undefined }), caps, NOW).allowConditionalCreate, false);
	// server says ineligible => no silent create either
	assert.strictEqual(M.nudgeDecision(bootBase({ nudge_state: { eligible: false } }), caps, NOW).allowConditionalCreate, false);
});

// ----------------------------------------------------- enforcement decision

// A boot with an enforce verdict in scope, 0 creds, grace remaining.
function enfBoot(over) {
	const enf = Object.assign(
		{
			policy: "Enforce",
			effective: "enforce",
			in_scope: true,
			blocking: false,
			grace_remaining: 3,
			grace_total: 3,
			allow_hybrid: true,
			incapable_policy: "degrade",
			reason: "grace",
		},
		(over && over.enforcement) || {}
	);
	return Object.assign({ credential_count: 0 }, over || {}, { enforcement: enf });
}

test("enforcementDecision: not enforcing when off/nudge/out-of-scope/satisfied", () => {
	assert.strictEqual(M.enforcementDecision({}, {}).reason, "not_enforcing");
	assert.strictEqual(
		M.enforcementDecision(enfBoot({ enforcement: { effective: "nudge" } }), { supported: true }).reason,
		"not_enforcing"
	);
	assert.strictEqual(
		M.enforcementDecision(enfBoot({ enforcement: { in_scope: false } }), { supported: true }).reason,
		"not_enforcing"
	);
	// already holds a passkey ⇒ satisfied
	assert.strictEqual(
		M.enforcementDecision(enfBoot({ credential_count: 1 }), { supported: true }).reason,
		"satisfied"
	);
});

test("enforcementDecision: capable device shows the enforce variant; grace vs blocking", () => {
	const grace = M.enforcementDecision(enfBoot(), { supported: true, uvpaa: true });
	assert.strictEqual(grace.show, true);
	assert.strictEqual(grace.variant, "enforce");
	assert.strictEqual(grace.blocking, false);
	assert.strictEqual(grace.graceRemaining, 3);
	assert.strictEqual(grace.reason, "enforce_grace");

	const block = M.enforcementDecision(
		enfBoot({ enforcement: { blocking: true, grace_remaining: 0 } }),
		{ supported: true, uvpaa: true }
	);
	assert.strictEqual(block.blocking, true);
	assert.strictEqual(block.reason, "enforce_blocking");
});

test("enforcementDecision: unknown capability counts as capable (tri-state)", () => {
	// uvpaa unknown (null) + hybrid unknown ⇒ still show the enroll gate, never dead-end.
	const d = M.enforcementDecision(enfBoot(), { supported: true, uvpaa: null, hybrid: null });
	assert.strictEqual(d.variant, "enforce");
	assert.strictEqual(d.show, true);
});

test("enforcementDecision: no platform authenticator but hybrid allowed ⇒ enroll via phone", () => {
	const d = M.enforcementDecision(enfBoot(), { supported: true, uvpaa: false, hybrid: true });
	assert.strictEqual(d.variant, "enforce");
	assert.strictEqual(d.allowHybrid, true);
});

test("enforcementDecision: genuinely incapable device degrades to nudge (default)", () => {
	const d = M.enforcementDecision(enfBoot(), { supported: false, uvpaa: false, hybrid: false });
	assert.strictEqual(d.variant, "nudge");
	assert.strictEqual(d.blocking, false);
	assert.strictEqual(d.reason, "incapable_degrade");
	// uvpaa false + hybrid false + allow_hybrid false ⇒ still incapable
	const d2 = M.enforcementDecision(
		enfBoot({ enforcement: { allow_hybrid: false } }),
		{ supported: true, uvpaa: false, hybrid: true }
	);
	assert.strictEqual(d2.variant, "nudge");
});

test("enforcementDecision: incapable + Block+Notify blocks and flags the admin", () => {
	const d = M.enforcementDecision(
		enfBoot({ enforcement: { incapable_policy: "block_notify" } }),
		{ supported: false }
	);
	assert.strictEqual(d.variant, "enforce");
	assert.strictEqual(d.blocking, true);
	assert.strictEqual(d.notifyAdmin, true);
	assert.strictEqual(d.reason, "incapable_block_notify");
});

// ---------------------------------------------------------- upsell decision

test("upsellDecision: flag + cadence => show; no flag => no show", () => {
	const store = (k) => (k === M.UPSELL_FLAG_KEY ? "1" : null);
	assert.strictEqual(M.upsellDecision(bootBase(), { supported: true, uvpaa: true }, store, NOW).showUpsell, true);
	assert.strictEqual(M.upsellDecision(bootBase(), { supported: true }, () => null, NOW).reason, "no_flag");
});

test("upsellDecision: NOT gated on 0 credentials (the user just signed in)", () => {
	const store = () => "1";
	// credential_count > 0 must still allow the upsell (unlike the enrollment nudge)
	assert.strictEqual(
		M.upsellDecision(bootBase({ credential_count: 1 }), { supported: true, uvpaa: true }, store, NOW).showUpsell,
		true
	);
});

test("upsellDecision: cadence-capped (declines/opt_out) + platform-authenticator gate", () => {
	const store = () => "1";
	assert.strictEqual(
		M.upsellDecision(bootBase({ nudge_state: { declines: 3, eligible: true } }), { supported: true, uvpaa: true }, store, NOW).reason,
		"cadence_capped"
	);
	assert.strictEqual(
		M.upsellDecision(bootBase({ nudge_state: { opt_out: 1, eligible: true } }), { supported: true, uvpaa: true }, store, NOW).reason,
		"cadence_capped"
	);
	assert.strictEqual(
		M.upsellDecision(bootBase(), { supported: true, uvpaa: false }, store, NOW).reason,
		"no_platform_authenticator"
	);
	// server upsell_eligible flag overrides the client cadence
	assert.strictEqual(
		M.upsellDecision(bootBase({ upsell_eligible: false }), { supported: true, uvpaa: true }, store, NOW).reason,
		"cadence_capped"
	);
});

// ---------------------------------------------------------- settings banners

test("settingsBanners: RP-ID one-way-door warning is always present", () => {
	const b = M.settingsBanners({ login_with_passkey: 1 }, {});
	assert.ok(b.some((x) => x.key === M.COPY.rpIdOneWayDoor && x.level === "warning"));
});

test("settingsBanners: no-RP-ID error when a mode is enabled but nothing resolves (A1)", () => {
	// resolvedRpId is now server-truth; blank ⇒ Save WILL fail, so warn inline.
	const b = M.settingsBanners({ login_with_passkey: 1 }, { currentHost: "staging.example.com" });
	const unresolved = b.find((x) => x.key === M.COPY.rpIdUnresolved);
	assert.ok(unresolved && unresolved.level === "error", "expected an rpIdUnresolved error banner");
	assert.deepStrictEqual(unresolved.args, ["staging.example.com"]);
	// Resolves ⇒ no unresolved banner; and no mode enabled ⇒ no unresolved banner either.
	const resolved = M.settingsBanners({ login_with_passkey: 1 }, { resolvedRpId: "example.com", currentHost: "example.com" });
	assert.ok(!resolved.some((x) => x.key === M.COPY.rpIdUnresolved));
	const off = M.settingsBanners({ login_with_passkey: 0, passkey_as_second_factor: 0 }, {});
	assert.ok(!off.some((x) => x.key === M.COPY.rpIdUnresolved));
});

test("settingsBanners: host mismatch is suppressed when no RP ID resolves", () => {
	// Only diagnose a host mismatch once an RP ID actually resolves — otherwise the
	// unresolved banner is the real story (a null rpId + custom origins must not
	// masquerade as a mismatch).
	const b = M.settingsBanners(
		{ login_with_passkey: 1 },
		{ currentHost: "staging.example.com", resolvedRpId: null, resolvedOrigins: ["https://other.example.com"] }
	);
	assert.ok(!b.some((x) => x.key === M.COPY.hostMismatch));
	assert.ok(b.some((x) => x.key === M.COPY.rpIdUnresolved));
});

test("settingsBanners: host mismatch when current host not in resolved origins", () => {
	const b = M.settingsBanners(
		{ login_with_passkey: 1 },
		{ currentHost: "staging.example.com", resolvedRpId: "example.com", resolvedOrigins: ["https://example.com"] }
	);
	assert.ok(b.some((x) => x.key === M.COPY.hostMismatch && x.level === "error"));
	// match => no banner
	const b2 = M.settingsBanners(
		{ login_with_passkey: 1 },
		{ currentHost: "example.com", resolvedOrigins: ["https://example.com"] }
	);
	assert.ok(!b2.some((x) => x.key === M.COPY.hostMismatch));
});

test("settingsBanners: 2FA needs core two-factor; notify-off + dead-combo warnings", () => {
	const b = M.settingsBanners(
		{ passkey_as_second_factor: 1, passkey_notify_on_change: 0 },
		{ coreTwoFactor: 0, disablePassLogin: 1 }
	);
	assert.ok(b.some((x) => x.key === M.COPY.twofaRequiresCore && x.level === "error"));
	assert.ok(b.some((x) => x.key === M.COPY.deadTwofaCombo && x.level === "warning"));
	assert.ok(b.some((x) => x.key === M.COPY.notifyOffWeakens && x.level === "warning"));
});

test("settingsBanners: rows 5/15 strand-guard + all-modes-off when no mode enabled", () => {
	const b = M.settingsBanners(
		{ login_with_passkey: 0, passkey_as_second_factor: 0 },
		{ passkeyOnlyUserCount: 4 }
	);
	const strand = b.find((x) => x.key === M.COPY.strandsPasskeyOnlyUsers);
	assert.ok(strand && strand.level === "error");
	assert.deepStrictEqual(strand.args, [4]);
	assert.ok(b.some((x) => x.key === M.COPY.allModesOff && x.level === "info"));
});

// ------------------------------------------------ enrollment ladder banners

test("roleNames normalises child rows / strings / missing tables", () => {
	assert.deepStrictEqual(M.roleNames([{ role: "System Manager" }, { role: "" }, "Sales User"]), [
		"System Manager",
		"Sales User",
	]);
	assert.deepStrictEqual(M.roleNames(undefined), []);
});

test("settingsBanners: Enforce After Date without a date is a Save-blocking error", () => {
	const b = M.settingsBanners(
		{ login_with_passkey: 1, passkey_enrollment_policy: "Enforce After Date" },
		{}
	);
	assert.ok(b.some((x) => x.key === M.COPY.enforceNoDate && x.level === "error"));
	// with a date ⇒ gone
	const ok = M.settingsBanners(
		{ login_with_passkey: 1, passkey_enrollment_policy: "Enforce After Date", passkey_enforce_after: "2026-08-01" },
		{ passkey_enforce_exempt_roles: [{ role: "System Manager" }] }
	);
	assert.ok(!ok.some((x) => x.key === M.COPY.enforceNoDate));
});

test("settingsBanners: enforcing while no mode enabled warns it is inert", () => {
	const b = M.settingsBanners(
		{ login_with_passkey: 0, passkey_as_second_factor: 0, passkey_enrollment_policy: "Enforce" },
		{ passkey_enforce_exempt_roles: [{ role: "System Manager" }] }
	);
	assert.ok(b.some((x) => x.key === M.COPY.enforceNoMode && x.level === "warning"));
});

test("settingsBanners: self-lockout warning when enforcing all users without System Manager exempt", () => {
	const doc = { login_with_passkey: 1, passkey_enrollment_policy: "Enforce", passkey_enforce_scope: "All Users" };
	const b = M.settingsBanners(doc, {});
	assert.ok(b.some((x) => x.key === M.COPY.enforceSelfLockout && x.level === "warning"));
	// System Manager exempt ⇒ suppressed
	doc.passkey_enforce_exempt_roles = [{ role: "System Manager" }];
	assert.ok(!M.settingsBanners(doc, {}).some((x) => x.key === M.COPY.enforceSelfLockout));
});

test("settingsBanners: Selected Roles with no roles enforces nobody (warning)", () => {
	const b = M.settingsBanners(
		{
			login_with_passkey: 1,
			passkey_enrollment_policy: "Enforce",
			passkey_enforce_scope: "Selected Roles",
			passkey_enforce_roles: [],
			passkey_enforce_exempt_roles: [{ role: "System Manager" }],
		},
		{}
	);
	assert.ok(b.some((x) => x.key === M.COPY.enforceEmptyRoles && x.level === "warning"));
});

test("settingsBanners: Block+Notify incapable policy warns; report-only preview count", () => {
	const b = M.settingsBanners(
		{
			login_with_passkey: 1,
			passkey_enrollment_policy: "Enforce",
			passkey_enforce_incapable: "Block + Notify Admin",
			passkey_enforce_exempt_roles: [{ role: "System Manager" }],
		},
		{ wouldBeBlockedCount: 7 }
	);
	assert.ok(b.some((x) => x.key === M.COPY.enforceBlockIncapable && x.level === "warning"));
	const preview = b.find((x) => x.key === M.COPY.enforcePreview);
	assert.ok(preview && preview.level === "info");
	assert.deepStrictEqual(preview.args, [7]);
});

test("settingsBanners: no enforcement banners under Nudge / Off", () => {
	const nudge = M.settingsBanners({ login_with_passkey: 1, passkey_enrollment_policy: "Nudge" }, { wouldBeBlockedCount: 3 });
	assert.ok(!nudge.some((x) => [M.COPY.enforceNoMode, M.COPY.enforceSelfLockout, M.COPY.enforcePreview].indexOf(x.key) !== -1));
});

// ---------------------------------------------------- security-posture panel

test("posturePanel: passes the verdict headline + tone through, no copy of its own", () => {
	const p = M.posturePanel({
		verdict: { headline: "Passkeys can currently be bypassed via: password sign-in.", tone: "high", can_bypass: true },
		rows: [],
	});
	assert.strictEqual(p.headline.text, "Passkeys can currently be bypassed via: password sign-in.");
	assert.strictEqual(p.headline.tone, "high");
	assert.strictEqual(p.headline.canBypass, true);
	assert.deepStrictEqual(p.rows, []);
});

test("posturePanel: sorts rows high→medium→low→info, disclaimer (detectable:false) always last", () => {
	const p = M.posturePanel({
		verdict: { headline: "x", tone: "high", can_bypass: true },
		rows: [
			{ code: "custom_apps", severity: "info", what: "custom", detectable: false },
			{ code: "sign_count_soft", severity: "low", what: "soft" },
			{ code: "password_login", severity: "high", what: "pw" },
			{ code: "core_2fa_on", severity: "info", what: "2fa" },
			{ code: "email_link", severity: "medium", what: "email" },
		],
	});
	assert.deepStrictEqual(
		p.rows.map((r) => r.code),
		["password_login", "email_link", "sign_count_soft", "core_2fa_on", "custom_apps"]
	);
	// the disclaimer sinks past the same-severity info row despite equal severity
	assert.strictEqual(p.rows[p.rows.length - 1].code, "custom_apps");
});

test("posturePanel: preserves server order within a severity bucket (stable)", () => {
	const p = M.posturePanel({
		verdict: {},
		rows: [
			{ code: "password_login", severity: "high" },
			{ code: "social_login", severity: "high" },
			{ code: "ldap", severity: "high" },
		],
	});
	assert.deepStrictEqual(p.rows.map((r) => r.code), ["password_login", "social_login", "ldap"]);
});

test("posturePanel: 'good' verdict + empty/absent response degrade cleanly", () => {
	const good = M.posturePanel({ verdict: { headline: "No stock bypass paths detected.", tone: "good", can_bypass: false } });
	assert.strictEqual(good.headline.tone, "good");
	assert.strictEqual(good.headline.canBypass, false);
	assert.deepStrictEqual(good.rows, []);
	const empty = M.posturePanel();
	assert.strictEqual(empty.headline.text, "");
	assert.strictEqual(empty.headline.tone, "info");
	assert.deepStrictEqual(empty.rows, []);
});

test("posturePanel: normalises row fields + detectable default (true)", () => {
	const p = M.posturePanel({ verdict: {}, rows: [{ severity: "medium", what: "w", why: "y", recommendation: "fix" }] });
	assert.deepStrictEqual(p.rows[0], {
		code: "", severity: "medium", what: "w", why: "y", recommendation: "fix", detectable: true,
	});
});

// ---------------------------------------------------- security-posture report (CTA)

test("postureRowMark: maps severity to the tick/flag language", () => {
	assert.strictEqual(M.postureRowMark({ severity: "high" }), "flag");
	assert.strictEqual(M.postureRowMark({ severity: "medium" }), "warn");
	assert.strictEqual(M.postureRowMark({ severity: "low" }), "tune");
	assert.strictEqual(M.postureRowMark({ severity: "info" }), "note");
	// an undetectable row is a neutral note regardless of its (info) severity
	assert.strictEqual(M.postureRowMark({ severity: "info", detectable: false }), "note");
	// unknown / missing severity degrades to a note, never throws
	assert.strictEqual(M.postureRowMark({}), "note");
	assert.strictEqual(M.postureRowMark(), "note");
});

test("postureReport: 'good' verdict is all-clear with zero actions (the satisfying tick)", () => {
	const r = M.postureReport({
		verdict: {
			headline: "No stock bypass paths detected — passkeys are the only stock way to sign in.",
			tone: "good",
			can_bypass: false,
		},
		rows: [
			{ code: "core_2fa_on", severity: "info", what: "2FA is on", recommendation: "No change needed" },
			{ code: "sign_count_soft", severity: "low", what: "hard-fail off", recommendation: "turn it on" },
			{ code: "custom_apps", severity: "info", what: "custom apps", detectable: false },
		],
	});
	assert.strictEqual(r.summary.tone, "good");
	assert.strictEqual(r.summary.allClear, true);
	assert.strictEqual(r.summary.canBypass, false);
	assert.strictEqual(r.summary.actionCount, 0); // low/info are not "action" items
	assert.strictEqual(r.summary.rowCount, 3);
	assert.strictEqual(r.headline.text.indexOf("No stock bypass paths") === 0, true);
});

test("postureReport: bypass verdict counts flags+warnings as actions, marks each row", () => {
	const r = M.postureReport({
		verdict: { headline: "Passkeys can currently be bypassed via: password sign-in.", tone: "high", can_bypass: true },
		rows: [
			{ code: "custom_apps", severity: "info", what: "custom", detectable: false },
			{ code: "sign_count_soft", severity: "low", what: "soft" },
			{ code: "password_login", severity: "high", what: "pw", recommendation: "disable it" },
			{ code: "email_link", severity: "medium", what: "email", recommendation: "turn it off" },
		],
	});
	// ordering is inherited from posturePanel: high, medium, low, then the disclaimer last
	assert.deepStrictEqual(r.rows.map((x) => x.code), ["password_login", "email_link", "sign_count_soft", "custom_apps"]);
	assert.deepStrictEqual(r.rows.map((x) => x.mark), ["flag", "warn", "tune", "note"]);
	assert.strictEqual(r.summary.tone, "high");
	assert.strictEqual(r.summary.allClear, false);
	assert.strictEqual(r.summary.canBypass, true);
	assert.strictEqual(r.summary.actionCount, 2); // one flag + one warn
});

test("postureReport: 'info' (passkeys not active) is neither all-clear nor a bypass", () => {
	const r = M.postureReport({
		verdict: { headline: "Passkeys are not an active login factor on this site.", tone: "info", can_bypass: false },
		rows: [{ code: "no_mode", severity: "info", what: "not active" }],
	});
	assert.strictEqual(r.summary.tone, "info");
	assert.strictEqual(r.summary.allClear, false);
	assert.strictEqual(r.summary.canBypass, false);
	assert.strictEqual(r.summary.actionCount, 0);
});

test("postureReport: empty/absent response degrades cleanly", () => {
	const r = M.postureReport();
	assert.strictEqual(r.summary.tone, "info");
	assert.strictEqual(r.summary.allClear, false);
	assert.strictEqual(r.summary.actionCount, 0);
	assert.strictEqual(r.summary.rowCount, 0);
	assert.deepStrictEqual(r.rows, []);
});

// ---------------------------------------------------------- origins + signal

test("originsIncludeHost / originHost normalise scheme + path", () => {
	assert.strictEqual(M.originHost("https://Example.com:8000/login"), "example.com:8000");
	assert.strictEqual(M.originsIncludeHost(["https://a.com", "https://b.com"], "b.com"), true);
	assert.strictEqual(M.originsIncludeHost(["https://a.com"], "b.com"), false);
});

test("signalPayload: shapes user_handle + credential_ids, else null", () => {
	assert.deepStrictEqual(
		M.signalPayload({ signal: { user_handle: "uh", credential_ids: ["a", "b"] } }),
		{ userHandle: "uh", allAcceptedCredentialIds: ["a", "b"] }
	);
	assert.strictEqual(M.signalPayload({ signal: { user_handle: "uh" } }), null);
	assert.strictEqual(M.signalPayload(null), null);
});

test("F3: an EMPTY credential_ids list passes through intentionally (last-delete ⇒ provider hides all)", () => {
	// A non-array is rejected (nothing to signal); [] is a valid, deliberate hide-all.
	assert.deepStrictEqual(
		M.signalPayload({ signal: { user_handle: "uh", credential_ids: [] } }),
		{ userHandle: "uh", allAcceptedCredentialIds: [] }
	);
});

test("F2: currentUserDetailsPayload shapes {userHandle, name, displayName}", () => {
	assert.deepStrictEqual(
		M.currentUserDetailsPayload({
			user_handle: "uh",
			name: "user@example.com",
			display_name: "Ada Lovelace",
		}),
		{ userHandle: "uh", name: "user@example.com", displayName: "Ada Lovelace" }
	);
	// also reads a verify_registration-style nested signal block
	assert.deepStrictEqual(
		M.currentUserDetailsPayload({ signal: { user_handle: "uh", name: "n", display_name: "d" } }),
		{ userHandle: "uh", name: "n", displayName: "d" }
	);
});

test("F2: currentUserDetailsPayload mirrors a lone field so neither name nor displayName is blank", () => {
	assert.deepStrictEqual(
		M.currentUserDetailsPayload({ user_handle: "uh", display_name: "Ada" }),
		{ userHandle: "uh", name: "Ada", displayName: "Ada" }
	);
	assert.deepStrictEqual(
		M.currentUserDetailsPayload({ user_handle: "uh", name: "ada@x.io" }),
		{ userHandle: "uh", name: "ada@x.io", displayName: "ada@x.io" }
	);
});

test("F2: currentUserDetailsPayload returns null with no handle or no name/displayName", () => {
	assert.strictEqual(M.currentUserDetailsPayload({ name: "n", display_name: "d" }), null);
	assert.strictEqual(M.currentUserDetailsPayload({ user_handle: "uh" }), null);
	assert.strictEqual(M.currentUserDetailsPayload(null), null);
});

// ------------------------------------------------------- deriveOrigins (C7)
// Client mirror of server policy.resolve_origins: the implicit https://<rp_id>
// origin is ALWAYS included, then the custom lines (deduped, order preserved).

test("deriveOrigins: implicit https://<rp_id> origin always leads the list", () => {
	assert.deepStrictEqual(M.deriveOrigins("", "example.com"), ["https://example.com"]);
	assert.deepStrictEqual(M.deriveOrigins("   \n\n", "example.com"), ["https://example.com"]);
	assert.deepStrictEqual(
		M.deriveOrigins("https://app.example.com\nhttps://admin.example.com", "example.com"),
		["https://example.com", "https://app.example.com", "https://admin.example.com"]
	);
});

test("deriveOrigins: dedupes an explicitly-listed implicit origin (no double entry)", () => {
	assert.deepStrictEqual(
		M.deriveOrigins("https://example.com\nhttps://app.example.com", "example.com"),
		["https://example.com", "https://app.example.com"]
	);
});

test("C7: a non-empty origins list without the rp_id origin does NOT show a false host-mismatch", () => {
	// The settings form used to drop the implicit origin for a non-empty list, so a
	// healthy site (rp_id == current host) got a bogus level:error mismatch banner.
	const rpId = "example.com";
	const origins = M.deriveOrigins("https://app.example.com", rpId); // list omits the bare host
	const ctx = { currentHost: "example.com", resolvedRpId: rpId, resolvedOrigins: origins };
	const banners = M.settingsBanners({ login_with_passkey: 1, passkey_notify_on_change: 1 }, ctx);
	const mismatch = banners.some((b) => b.level === "error" && b.key === M.COPY.hostMismatch);
	assert.strictEqual(mismatch, false, "implicit https://<rp_id> origin must suppress the false mismatch");
});

// ------------------------------------------------------------------ C8 (note)
// The RP-ID "one-way door" confirm now GATES the save: on Cancel/Esc/backdrop the
// passkey_settings.js handler reverts passkey_rp_id to its last-saved value via
// `frm.set_value(...)` on the dialog's `hide.bs.modal`, and acks the reverted value
// first so the re-fired change event short-circuits (no re-prompt loop). That path
// is frappe-form + frappe.warn (bootstrap modal) bound, so it cannot run under
// `node --test` (no bench/jsdom). MANUAL CHECK on a bench:
//   1. Open Passkey Settings on a saved doc, change the RP ID, Cancel the warn →
//      the field snaps back to the saved value and the doc is NOT dirty.
//   2. Change it again, click "Yes, change it" → the value sticks and can be saved.
//   3. Esc / click-outside the warn behaves like Cancel (reverts).
