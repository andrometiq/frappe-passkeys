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

test("accessibleActionName translates the template before formatting", () => {
	const translations = {
		"Rename passkey {0}": "Renommer la cle {0}",
		"Delete passkey {0}": "Supprimer la cle {0}",
	};
	const tr = (key) => translations[key] || key;
	assert.strictEqual(M.accessibleActionName("rename", "Telephone", tr), "Renommer la cle Telephone");
	assert.strictEqual(
		M.credentialViewModel({ label: "Telephone" }, { translate: tr }).a11y.del,
		"Supprimer la cle Telephone"
	);
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

// ---------------------------------------------------------- nudge decision

// Mirrors the server bootinfo: `nudge_state.eligible` and `upsell_eligible` are the
// authoritative cadence verdicts.
function bootBase(over) {
	return deepAssign(
		{
			modes: { first_factor: true, second_factor: false },
			enabled: true,
			credential_count: 0,
			nudge_state: { declines: 0, last_shown: null, opt_out: 0, eligible: true },
			post_login_method: "password",
			conditional_create: true,
			upsell_eligible: true,
		},
		over || {}
	);
}
function deepAssign(base, over) {
	const out = Object.assign({}, base, over);
	if (over.nudge_state) out.nudge_state = Object.assign({}, base.nudge_state, over.nudge_state);
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

test("nudgeDecision: a boot without the server verdict never nudges", () => {
	const d = M.nudgeDecision({ credential_count: 0, nudge_state: { declines: 0 } }, { supported: true }, NOW);
	assert.strictEqual(d.showNudge, false);
	assert.strictEqual(d.reason, "server_ineligible");
});

test("nudgeDecision: conditional create gated on server eligible ∧ knob ∧ caps ∧ password window", () => {
	const caps = { supported: true, conditionalCreate: true };
	assert.strictEqual(M.nudgeDecision(bootBase(), caps, NOW).allowConditionalCreate, true);
	// email-link / external login: window not password-seeded
	assert.strictEqual(M.nudgeDecision(bootBase({ post_login_method: "external" }), caps, NOW).allowConditionalCreate, false);
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
			enforcing: true,
			effective: "enforce",
			in_scope: true,
			blocking: false,
			grace_remaining: 3,
			grace_total: 3,
			incapable_policy: "degrade",
			degrade_nudge_eligible: true,
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

test("enforcementDecision: honors a non-default server grace budget verbatim (no hardcoded 3)", () => {
	// The product-owner report was "grace is only three, always three". The client view-model
	// must surface EXACTLY the grace the server computed — never a baked-in default of 3 — so
	// the "N sign-ins left" copy is honest for any configured budget.
	const d = M.enforcementDecision(
		enfBoot({ enforcement: { grace_remaining: 5, grace_total: 5, blocking: false } }),
		{ supported: true, uvpaa: true }
	);
	assert.strictEqual(d.show, true);
	assert.strictEqual(d.variant, "enforce");
	assert.strictEqual(d.graceRemaining, 5);
	assert.strictEqual(d.blocking, false);
	assert.strictEqual(d.reason, "enforce_grace");

	// At the configured boundary the server flips `blocking`; the client mirrors it exactly.
	const atBoundary = M.enforcementDecision(
		enfBoot({ enforcement: { grace_remaining: 0, grace_total: 5, blocking: true } }),
		{ supported: true, uvpaa: true }
	);
	assert.strictEqual(atBoundary.graceRemaining, 0);
	assert.strictEqual(atBoundary.blocking, true);
	assert.strictEqual(atBoundary.reason, "enforce_blocking");
});

test("enforcementDecision: unknown capability counts as capable (tri-state)", () => {
	// uvpaa unknown (null) + hybrid unknown ⇒ still show the enroll gate, never dead-end.
	const d = M.enforcementDecision(enfBoot(), { supported: true, uvpaa: null, hybrid: null });
	assert.strictEqual(d.variant, "enforce");
	assert.strictEqual(d.show, true);
});

test("enforcementDecision: no platform authenticator but hybrid transport ⇒ enroll via phone", () => {
	const d = M.enforcementDecision(enfBoot(), { supported: true, uvpaa: false, hybrid: true });
	assert.strictEqual(d.variant, "enforce");
	assert.strictEqual(d.show, true);
	assert.strictEqual(d.allowHybrid, undefined);
});

test("enforcementDecision: genuinely incapable device degrades to nudge (default)", () => {
	const d = M.enforcementDecision(enfBoot(), { supported: false, uvpaa: false, hybrid: false });
	assert.strictEqual(d.variant, "nudge");
	assert.strictEqual(d.blocking, false);
	assert.strictEqual(d.reason, "incapable_degrade");
	// uvpaa false and hybrid false is incapable; hybrid true is capable even without uvpaa
	const viaPhone = M.enforcementDecision(enfBoot(), { supported: true, uvpaa: false, hybrid: true });
	assert.strictEqual(viaPhone.variant, "enforce");
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

test("upsellDecision: server cadence + platform-authenticator gate", () => {
	const store = () => "1";
	assert.strictEqual(
		M.upsellDecision(bootBase(), { supported: true, uvpaa: false }, store, NOW).reason,
		"no_platform_authenticator"
	);
	for (const upsell of [false, undefined]) {
		assert.strictEqual(
			M.upsellDecision(bootBase({ upsell_eligible: upsell }), { supported: true, uvpaa: true }, store, NOW).reason,
			"cadence_capped"
		);
	}
});

// ------------------------------------------------------------ impersonation

test("isImpersonated: only the server's boolean true counts", () => {
	assert.strictEqual(M.isImpersonated({ impersonated: true }), true);
	for (const value of [false, undefined, 1, "true"]) {
		assert.strictEqual(M.isImpersonated({ impersonated: value }), false, String(value));
	}
	assert.strictEqual(M.isImpersonated(null), false);
});

test("an impersonated session is never prompted, whatever the server cadence says", () => {
	const caps = { supported: true, uvpaa: true, conditionalCreate: true };
	const nudge = M.nudgeDecision(bootBase({ impersonated: true }), caps, NOW);
	assert.strictEqual(nudge.showNudge, false);
	assert.strictEqual(nudge.allowConditionalCreate, false);
	assert.strictEqual(nudge.reason, "impersonated");
	assert.strictEqual(M.nudgeDecision(bootBase(), caps, NOW).showNudge, true, "control: the same boot nudges the user");

	const upsell = M.upsellDecision(bootBase({ impersonated: true }), caps, () => "1", NOW);
	assert.strictEqual(upsell.showUpsell, false);
	assert.strictEqual(upsell.reason, "impersonated");

	// A blocking gate, and an incapable device under Block + Notify Admin: neither walls the
	// impersonator in, and neither reports the impersonator's device against the user.
	const verdicts = [
		{ blocking: true, grace_remaining: 0 },
		{ blocking: false, grace_remaining: 2 },
		{ incapable_policy: "block_notify" },
	];
	for (const enforcement of verdicts) {
		for (const deviceCaps of [caps, { supported: false }]) {
			const d = M.enforcementDecision(enfBoot({ impersonated: true, enforcement }), deviceCaps);
			assert.deepStrictEqual(
				[d.show, d.blocking, d.notifyAdmin, d.reason],
				[false, false, false, "impersonated"],
				JSON.stringify([enforcement, deviceCaps])
			);
		}
	}
	assert.strictEqual(
		M.enforcementDecision(enfBoot({ enforcement: { blocking: true, grace_remaining: 0 } }), caps).blocking,
		true,
		"control: the same verdict blocks the user"
	);
});

// ---------------------------------------------------------- settings banners

test("settingsBanners: RP-ID one-way-door is NOT a top banner (moved to the field description)", () => {
	// The caution now lives inline on the passkey_rp_id field (near its field, subtle) +
	// the loud typed confirm on an actual change — never a permanent, attention-grabbing
	// top banner.
	const b = M.settingsBanners({ login_with_passkey: 1 }, {});
	assert.ok(!b.some((x) => x.key === M.COPY.rpIdOneWayDoor));
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
		{
			currentHost: "staging.example.com",
			currentOrigin: "https://staging.example.com",
			resolvedRpId: null,
			resolvedOrigins: ["https://other.example.com"],
		}
	);
	assert.ok(!b.some((x) => x.key === M.COPY.hostMismatch));
	assert.ok(b.some((x) => x.key === M.COPY.rpIdUnresolved));
});

test("settingsBanners: host mismatch when current host not in resolved origins", () => {
	const b = M.settingsBanners(
		{ login_with_passkey: 1 },
		{
			currentHost: "staging.example.com",
			currentOrigin: "https://staging.example.com",
			resolvedRpId: "example.com",
			resolvedOrigins: ["https://example.com"],
		}
	);
	assert.ok(b.some((x) => x.key === M.COPY.hostMismatch && x.level === "error"));
	const b2 = M.settingsBanners(
		{ login_with_passkey: 1 },
		{
			currentHost: "example.com",
			currentOrigin: "https://example.com",
			resolvedRpId: "example.com",
			resolvedOrigins: ["https://example.com"],
		}
	);
	assert.ok(!b2.some((x) => x.key === M.COPY.hostMismatch));
});

test("settingsBanners: host mismatch compares the full origin, port included", () => {
	const banners = (currentOrigin, resolvedOrigins) =>
		M.settingsBanners(
			{ login_with_passkey: 1 },
			{ currentHost: "localhost", currentOrigin, resolvedRpId: "localhost", resolvedOrigins }
		).some((x) => x.key === M.COPY.hostMismatch);
	// Every origin carries an explicit port and the page is served on it: no false alarm.
	assert.strictEqual(banners("http://localhost:8011", ["http://localhost:8011"]), false);
	// Same host, wrong port or scheme: the server would refuse the ceremony, so flag it.
	assert.strictEqual(banners("http://localhost:8000", ["http://localhost:8011"]), true);
	assert.strictEqual(banners("http://localhost:8011", ["https://localhost:8011"]), true);
	// An explicit default port is the same origin.
	assert.strictEqual(banners("https://example.com", ["https://Example.com:443/"]), false);
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

test("settingsBanners: a blank Starting on is not a Save-blocking error", () => {
	const b = M.settingsBanners(
		{
			login_with_passkey: 1,
			passkey_enforce_scope: "All users",
			passkey_enforce_privileged_always: 1,
		},
		{}
	);
	assert.ok(!b.some((x) => x.key === M.COPY.enforceNoDate));
	assert.strictEqual(M.COPY.enforceNoDate, undefined);
});

test("settingsBanners: enforcing while no mode enabled warns it is inert", () => {
	const b = M.settingsBanners(
		{
			login_with_passkey: 0,
			passkey_as_second_factor: 0,
			passkey_enforce_scope: "All users",
			passkey_enforce_privileged_always: 1,
		},
		{}
	);
	assert.ok(b.some((x) => x.key === M.COPY.enforceNoMode && x.level === "warning"));
});

test("settingsBanners: privileged-always opt-out warns only for Selected roles", () => {
	const doc = {
		login_with_passkey: 1,
		passkey_enforce_scope: "Selected roles",
		passkey_enforce_privileged_always: 0,
		passkey_enforce_roles: [{ role: "Sales User" }],
	};
	const b = M.settingsBanners(doc, {});
	assert.ok(b.some((x) => x.key === M.COPY.enforcePrivilegedOutside && x.level === "warning"));
	doc.passkey_enforce_privileged_always = 1;
	assert.ok(!M.settingsBanners(doc, {}).some((x) => x.key === M.COPY.enforcePrivilegedOutside));
	doc.passkey_enforce_scope = "All users";
	doc.passkey_enforce_privileged_always = 0;
	assert.ok(!M.settingsBanners(doc, {}).some((x) => x.key === M.COPY.enforcePrivilegedOutside));
});

test("settingsBanners: Selected roles with no roles enforces nobody (warning)", () => {
	const b = M.settingsBanners(
		{
			login_with_passkey: 1,
			passkey_enforce_scope: "Selected roles",
			passkey_enforce_roles: [],
			passkey_enforce_privileged_always: 1,
		},
		{}
	);
	assert.ok(b.some((x) => x.key === M.COPY.enforceEmptyRoles && x.level === "warning"));
});

test("settingsBanners: Block+Notify incapable policy warns; report-only preview count", () => {
	const b = M.settingsBanners(
		{
			login_with_passkey: 1,
			passkey_enforce_scope: "All users",
			passkey_enforce_incapable: "Block + Notify Admin",
			passkey_enforce_privileged_always: 1,
		},
		{ enforcementPreview: { count: 7, computed_at: "2026-10-20T10:00:00" } }
	);
	assert.ok(b.some((x) => x.key === M.COPY.enforceBlockIncapable && x.level === "warning"));
	const preview = b.find((x) => x.key === M.COPY.enforcePreview);
	assert.ok(preview && preview.level === "info");
	assert.deepStrictEqual(preview.args, [7, "2026-10-20T10:00:00"]);
	assert.strictEqual(preview.action, "recalculate");
});

test("settingsBanners: uncached and zero previews stay informational with a recalculate action", () => {
	const doc = { login_with_passkey: 1, passkey_enforce_scope: "All users" };
	const keys = (ctx) => M.settingsBanners(doc, ctx).map((x) => x.key);
	assert.ok(!keys({}).includes(M.COPY.enforcePreviewPending), "nothing before the form has fetched the context");
	const pending = M.settingsBanners(doc, { enforcementPreview: null }).find((x) => x.key === M.COPY.enforcePreviewPending);
	assert.deepStrictEqual(pending, { level: "info", key: "Not counted yet", args: [], muted: true, action: "recalculate" });
	const cached = M.settingsBanners(doc, { enforcementPreview: { count: 0, computed_at: "2026-10-20T10:00:00" } }).find((x) => x.key === M.COPY.enforcePreview);
	assert.strictEqual(cached.level, "info");
	assert.strictEqual(cached.muted, false);
	assert.strictEqual(cached.action, "recalculate");
	assert.deepStrictEqual(cached.args, [0, "2026-10-20T10:00:00"]);
});

test("settingsBanners: no enforcement banners when scope is No one and privileged is off", () => {
	const nudge = M.settingsBanners(
		{ login_with_passkey: 1, passkey_enforce_scope: "No one", passkey_enforce_privileged_always: 0, passkey_everyone_else: "Nudge" },
		{ enforcementPreview: { count: 3, computed_at: "2026-10-20T10:00:00" } }
	);
	assert.ok(!nudge.some((x) => [M.COPY.enforceNoMode, M.COPY.enforcePrivilegedOutside, M.COPY.enforcePreview].indexOf(x.key) !== -1));
});

// ---------------------------------------------------- security-posture panel

test("posturePanel: passes the verdict headline + tone through, no copy of its own", () => {
	const p = M.posturePanel({
		verdict: { headline: "Users can still sign in without a passkey via: password sign-in.", tone: "high", can_bypass: true },
		rows: [],
	});
	assert.strictEqual(p.headline.text, "Users can still sign in without a passkey via: password sign-in.");
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

test("postureReport: 'good' verdict marks low/info rows without flags", () => {
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
	assert.strictEqual(r.headline.tone, "good");
	assert.strictEqual(r.headline.canBypass, false);
	assert.strictEqual(r.rows.length, 3);
	assert.strictEqual(r.headline.text.indexOf("No stock bypass paths") === 0, true);
});

test("postureReport: bypass verdict marks each row", () => {
	const r = M.postureReport({
		verdict: { headline: "Users can still sign in without a passkey via: password sign-in.", tone: "high", can_bypass: true },
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
	assert.strictEqual(r.headline.tone, "high");
	assert.strictEqual(r.headline.canBypass, true);
});

test("postureReport: 'info' (passkeys not active) is not a bypass", () => {
	const r = M.postureReport({
		verdict: { headline: "Passkeys are not an active login factor on this site.", tone: "info", can_bypass: false },
		rows: [{ code: "no_mode", severity: "info", what: "not active" }],
	});
	assert.strictEqual(r.headline.tone, "info");
	assert.strictEqual(r.headline.canBypass, false);
});

test("postureReport: empty/absent response degrades cleanly", () => {
	const r = M.postureReport();
	assert.strictEqual(r.headline.tone, "info");
	assert.strictEqual(r.rows.length, 0);
	assert.deepStrictEqual(r.rows, []);
});

// ---------------------------------------------------------- origins + signal

test("originsIncludeOrigin / canonicalOrigin normalise case, default port and path", () => {
	assert.strictEqual(M.canonicalOrigin("https://Example.com:8000/login"), "https://example.com:8000");
	assert.strictEqual(M.canonicalOrigin("https://example.com:443"), "https://example.com");
	assert.strictEqual(M.canonicalOrigin("example.com"), null);
	assert.strictEqual(M.canonicalOrigin("localhost:8011"), null);
	assert.strictEqual(M.originsIncludeOrigin(["https://a.com", "https://b.com"], "https://b.com"), true);
	assert.strictEqual(M.originsIncludeOrigin(["https://a.com"], "https://b.com"), false);
	assert.strictEqual(M.originsIncludeOrigin(["https://a.com"], null), false);
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
// RP ID is credential scope, not an origin. The browser mirrors server policy from
// the exact configured site origin plus explicit passkey_origins only.

test("deriveOrigins: exact configured site origin leads explicit origins", () => {
	assert.deepStrictEqual(M.deriveOrigins("", "https://site.example.com:8443"), ["https://site.example.com:8443"]);
	assert.deepStrictEqual(M.deriveOrigins("   \n\n", "https://site.example.com"), ["https://site.example.com"]);
	assert.deepStrictEqual(
		M.deriveOrigins("https://app.example.com\nhttps://admin.example.com", "https://site.example.com"),
		["https://site.example.com", "https://app.example.com", "https://admin.example.com"]
	);
});

test("deriveOrigins: dedupes an explicitly-listed configured origin", () => {
	assert.deepStrictEqual(
		M.deriveOrigins("https://example.com\nhttps://app.example.com", "https://example.com"),
		["https://example.com", "https://app.example.com"]
	);
});

test("deriveOrigins never turns an RP ID-shaped value into an implicitly trusted HTTPS origin", () => {
	assert.deepStrictEqual(M.deriveOrigins("https://app.example.com", null), ["https://app.example.com"]);
	assert.deepStrictEqual(M.deriveOrigins("", null), []);
});

// ------------------------------------------------ passkey-only + native validation

test("passkeyOnlyAvailability requires two enabled credentials only when enabling", () => {
	assert.deepStrictEqual(M.passkeyOnlyAvailability(0, false), {
		enabledCount: 0, disabled: true, helpKey: "passkeyOnlyNeedsTwo",
	});
	assert.strictEqual(M.passkeyOnlyAvailability(1, false).disabled, true);
	assert.strictEqual(M.passkeyOnlyAvailability(2, false).disabled, false);
	assert.strictEqual(M.passkeyOnlyAvailability(0, true).disabled, false, "disabling must remain available");
});

test("validateAndroidFingerprints requires exactly 64 hex characters after presentation cleanup", () => {
	const hex = "ab".repeat(32);
	const valid = M.validateAndroidFingerprints("SHA-256 = " + hex + "\nsha256:" + hex.match(/../g).join(":"));
	assert.strictEqual(valid.valid, true);
	assert.strictEqual(valid.normalized.length, 1, "equivalent lines dedupe");
	assert.strictEqual(valid.normalized[0], hex.toUpperCase().match(/../g).join(":"));

	for (const malformed of ["ab".repeat(31), "ab".repeat(33), "g".repeat(64), "12:34"] ) {
		const result = M.validateAndroidFingerprints(malformed);
		assert.strictEqual(result.valid, false, malformed);
	}
});

test("createSessionEventRecorder coalesces retries and clears failed attempts", async () => {
	const values = new Map();
	const storage = {
		getItem: (key) => values.get(key) || null,
		setItem: (key, value) => values.set(key, value),
		removeItem: (key) => values.delete(key),
	};
	const record = M.createSessionEventRecorder(storage);
	let calls = 0;
	const first = record("session:event", async () => { calls += 1; return "ok"; });
	const second = record("session:event", async () => { calls += 1; return "duplicate"; });
	assert.strictEqual(await first, "ok");
	assert.deepStrictEqual(await second, { skipped: true });
	assert.strictEqual(calls, 1);

	await assert.rejects(record("retryable", async () => { throw new Error("offline"); }), /offline/);
	assert.strictEqual(await record("retryable", async () => "retried"), "retried");
});

test("signalCredentialState keeps registration/deletion parity, including an empty accepted list", () => {
	const calls = [];
	const PKC = {
		signalAllAcceptedCredentials: (data) => { calls.push(["accepted", data]); return Promise.resolve(); },
		signalCurrentUserDetails: (data) => { calls.push(["details", data]); return Promise.resolve(); },
	};
	const result = M.signalCredentialState(PKC, {
		signal: {
			rp_id: "example.com", user_handle: "handle", credential_ids: [],
			name: "user@example.com", display_name: "User",
		},
	});
	assert.deepStrictEqual(result, { accepted: true, details: true });
	assert.deepStrictEqual(calls[0][1], {
		rpId: "example.com", userId: "handle", allAcceptedCredentialIds: [],
	});
	assert.deepStrictEqual(calls[1][1], {
		rpId: "example.com", userId: "handle", name: "user@example.com", displayName: "User",
	});
});

for (const eligible of [true, false, undefined]) {
	test(`enforcementDecision: Degrade requires explicit server eligibility (${eligible})`, () => {
		const d = M.enforcementDecision(enfBoot({ enforcement: { degrade_nudge_eligible: eligible } }), { supported: false });
		assert.strictEqual(d.show, eligible === true);
		assert.strictEqual(d.variant, "nudge");
		assert.strictEqual(d.reason, eligible === true ? "incapable_degrade" : "incapable_degrade_capped");
	});
}


test("settings form fetches context on demand and recalculates only on request", () => {
	const fs = require("node:fs");
	const vm = require("node:vm");
	const calls = [];
	const alerts = [];
	let handlers;
	let paints = 0;
	const context = {
		frappe: {
			ui: { form: { on: (_doctype, value) => { handlers = value; } } },
			boot: { passkeys: { rp_id: "example.com" } },
			passkeys_manage_common: M,
			call: (options) => { calls.push(options); },
			show_alert: (options) => { alerts.push(options); },
			datetime: { str_to_user: (value) => `user:${value}` },
		},
		window: { location: { hostname: "example.com", origin: "https://example.com" } },
		__: (text) => text,
		$: (button) => button,
	};
	vm.createContext(context);
	vm.runInContext(fs.readFileSync(require.resolve("../../public/js/passkey_settings.js"), "utf8"), context);
	context.paintBanners = () => { paints += 1; };
	context.fetchSecurityPosture = () => {};
	const frm = { doc: {}, fields_dict: {}, set_df_property: () => {} };
	handlers.refresh(frm);
	assert.strictEqual(calls.length, 2);
	assert.ok(calls[0].method.endsWith(".get_resolved_rp_id"));
	assert.ok(calls[1].method.endsWith(".get_settings_context"));
	const preview = { count: 4, computed_at: "2026-10-20T10:00:00" };
	calls[1].callback({ message: { enforcement_preview: preview, core_two_factor_auth: true } });
	assert.strictEqual(paints, 2);
	assert.deepStrictEqual(
		{ ...context.buildContext(frm).enforcementPreview },
		{ count: 4, computed_at: "user:2026-10-20T10:00:00" }
	);
	assert.strictEqual(context.buildContext(frm).coreTwoFactor, true);
	let pollArgs;
	context.pollEnforcementPreview = (...args) => { pollArgs = args; };
	context.recalculateEnforcementPreview(frm, {});
	assert.ok(calls[2].method.endsWith(".recalculate_enforcement_preview"));
	assert.strictEqual(alerts.length, 0);
	const afterScan = 10;
	calls[2].callback({ message: { after_scan: afterScan } });
	assert.deepStrictEqual(pollArgs, [frm, afterScan]);
	assert.strictEqual(alerts[0].message, "Recounting in the background…");
});

for (const changedRpId of ["new.example.com", ""]) {
test(`RP ID confirm waits for blur or save, and asks once (${changedRpId || "blank"})`, async () => {
	const fs = require("node:fs");
	const vm = require("node:vm");
	let handlers;
	let blur;
	const warns = [];
	const context = {
		frappe: {
			ui: { form: { on: (_doctype, value) => { handlers = value; } } },
			boot: { passkeys: {} },
			passkeys_manage_common: M,
			passkeys_common: require("../../public/js/passkey_common.bundle.js"),
			call: options => options.callback({ message: { stop: { passkeys: 0, users: 0 }, start: { passkeys: 0, users: 0 }, new_off: false } }),
			warn: (...args) => {
				const dialog = { $wrapper: { on: (_event, handler) => { dialog.hide = handler; } } };
				warns.push({ args, dialog });
				return dialog;
			},
		},
		window: { location: { hostname: "example.com", origin: "https://example.com" } },
		__: (text) => text,
	};
	vm.createContext(context);
	vm.runInContext(fs.readFileSync(require.resolve("../../public/js/passkey_settings.js"), "utf8"), context);
	context.paintBanners = () => {};
	context.fetchResolvedRpId = () => {};
	context.fetchSettingsContext = () => {};
	context.fetchSecurityPosture = () => {};
	const values = [];
	const input = { off: () => input, on: (_event, handler) => { blur = handler; return input; } };
	let typed = "example.com";
	const frm = {
		doc: { passkey_rp_id: "example.com" },
		fields_dict: { passkey_rp_id: { $input: input, get_input_value: () => typed } },
		set_df_property: () => {},
		set_value: (field, value) => { values.push(value); frm.doc[field] = value; },
	};
	handlers.refresh(frm);
	assert.strictEqual(handlers.passkey_rp_id.name, "paintBanners", "typing only repaints the banners");
	// Typed but not yet debounced into the doc: blur commits the input's text first.
	typed = changedRpId;
	assert.strictEqual(warns.length, 0);
	blur();
	blur();
	await new Promise((resolve) => setImmediate(resolve));
	assert.strictEqual(frm.doc.passkey_rp_id, changedRpId, "blur commits the typed RP ID");
	assert.strictEqual(warns.length, 1, "one confirm per change, not per blur");
	warns[0].dialog.hide();
	assert.deepStrictEqual(values.slice(-1), ["example.com"], "Cancel reverts to the saved RP ID");
	typed = "example.com";

	frm.doc.passkey_rp_id = changedRpId;
	context.frappe.validated = true;
	handlers.validate(frm);
	assert.strictEqual(context.frappe.validated, false, "an unconfirmed change cannot be saved");
	assert.strictEqual(warns.length, 2);
	warns[1].args[2]();
	warns[1].dialog.hide();
	context.frappe.validated = true;
	handlers.validate(frm);
	assert.strictEqual(context.frappe.validated, true, "a confirmed change saves");
	assert.strictEqual(frm.doc.passkey_rp_id, changedRpId);
});

}

function previewPollingForm() {
	const calls = [];
	const timers = new Map();
	let timerId = 0;
	let handlers;
	const paints = [];
	const frm = { doc: { name: "Passkey Settings", modified: "2026-10-20 10:00:00.000000", __onload: { passkeys_preview_after_scan: 10 } }, is_dirty: () => false };
	const context = {
		frappe: {
			ui: { form: { on: (_doctype, value) => { handlers = value; } } },
			call: (options) => { calls.push(options); },
			show_alert: () => {},
		},
		__: (text) => text,
		$: (button) => button,
		setTimeout: (callback, delay) => {
			assert.strictEqual(delay, 3000);
			timers.set(++timerId, callback);
			return timerId;
		},
		clearTimeout: (id) => timers.delete(id),
	};
	require("node:vm").createContext(context);
	require("node:vm").runInContext(require("node:fs").readFileSync(
		require.resolve("../../public/js/passkey_settings.js"), "utf8"
	), context);
	context.paintBanners = (form) => { paints.push(form._passkey_settings_context); };
	return { context, frm, handlers, calls, timers, paints, tick() {
		assert.strictEqual(timers.size, 1);
		const [id, callback] = timers.entries().next().value;
		timers.delete(id);
		callback();
	} };
}

for (const trigger of ["recalculate", "save"]) {
	for (const staleScan of [9, 10]) {
		test(`settings ${trigger} waits for its threshold and repaints (stale scan ${staleScan})`, () => {
			const h = previewPollingForm();
			const threshold = 10;
			h.frm._passkey_settings_context = {
				enforcement_preview: { count: 2, computed_at: "2026-10-20 09:00:00.000000" },
			};
			if (trigger === "save") {
				h.frm.doc.__onload.passkeys_preview_after_scan = threshold;
				h.handlers.after_save(h.frm);
			} else {
				h.context.recalculateEnforcementPreview(h.frm, {});
				h.calls.shift().callback({ message: { after_scan: threshold } });
			}
			h.tick();
			assert.ok(h.calls[0].method.endsWith(".get_settings_context"));
			const stale = { enforcement_preview: { count: 3, scan: staleScan, computed_at: "2026-10-20 12:00:00.000000" } };
			h.calls.shift().callback({ message: stale });
			assert.strictEqual(h.paints.at(-1), stale);
			h.tick();
			const updated = { enforcement_preview: { count: 5, scan: 11, computed_at: "2026-10-20 09:00:00.000000" } };
			h.calls.shift().callback({ message: updated });
			assert.strictEqual(h.frm._passkey_settings_context, updated);
			assert.strictEqual(h.paints.at(-1), updated);
			assert.strictEqual(h.timers.size, 0);
		});
	}
}

test("settings preview polling stops at ten requests and replaces an existing loop", () => {
	const h = previewPollingForm();
	h.handlers.after_save(h.frm, "Passkey Settings", "Passkey Settings");
	h.handlers.after_save(h.frm, "Passkey Settings", "Passkey Settings");
	for (let i = 0; i < 10; i++) {
		h.tick();
		h.calls.at(-1).callback({ message: { enforcement_preview: { count: i, computed_at: "2026-10-20 09:00:00.000000" } } });
	}
	assert.strictEqual(h.calls.length, 10);
	assert.strictEqual(h.timers.size, 0);
});

for (const change of ["document", "modified", "dirty"]) {
	test(`settings preview polling ignores a response after changing ${change}`, () => {
		const h = previewPollingForm();
		h.handlers.after_save(h.frm, "Passkey Settings", "Passkey Settings");
		h.tick();
		if (change === "modified") h.frm.doc.modified = "2026-10-20 11:00:00.000000";
		if (change === "document") h.frm.doc = { name: "another" };
		if (change === "dirty") h.frm.is_dirty = () => true;
		h.calls[0].callback({ message: { enforcement_preview: { count: 5, scan: 11, computed_at: "2026-10-20 10:00:00.000000" } } });
		assert.strictEqual(h.paints.length, 0);
		assert.strictEqual(h.timers.size, 0);
	});
}


test("settings preview polling stops when the first preview appears", () => {
	const h = previewPollingForm();
	h.handlers.after_save(h.frm, "Passkey Settings", "Passkey Settings");
	h.tick();
	h.calls.shift().callback({ message: { enforcement_preview: null } });
	h.tick();
	const updated = { enforcement_preview: { count: 0, scan: 11, computed_at: "2026-10-20 10:00:00.000000" } };
	h.calls.shift().callback({ message: updated });
	assert.strictEqual(h.paints.at(-1), updated);
	assert.strictEqual(h.timers.size, 0);
});


test("a delayed refresh cannot replace a newer polled preview", () => {
	const h = previewPollingForm();
	h.handlers.after_save(h.frm, "Passkey Settings", "Passkey Settings");
	h.context.fetchSettingsContext(h.frm);
	const refresh = h.calls.shift();
	h.tick();
	const updated = { enforcement_preview: { count: 5, scan: 11, computed_at: "2026-10-20 10:00:00.000000" } };
	h.calls.shift().callback({ message: updated });
	refresh.callback({ message: { enforcement_preview: null } });
	assert.strictEqual(h.frm._passkey_settings_context, updated);
	assert.strictEqual(h.paints.at(-1), updated);
	assert.strictEqual(h.timers.size, 0);
});

test("settings save without onload threshold repaints for the full polling window", () => {
	const h = previewPollingForm();
	delete h.frm.doc.__onload;
	h.handlers.after_save(h.frm);
	for (let i = 0; i < 10; i++) {
		h.tick();
		const result = { enforcement_preview: { count: i, scan: 100 + i, computed_at: "2026-10-20 12:00:00" } };
		h.calls.at(-1).callback({ message: result });
		assert.strictEqual(h.paints.at(-1), result);
	}
	assert.strictEqual(h.calls.length, 10);
	assert.strictEqual(h.timers.size, 0);
});

test("RP provenance determines staleness, independently of enabled and flagged", () => {
	for (const [rp, site, stale] of [[" Example.COM ", "example.com", false], ["erp.example.com", "example.com", true], ["", "example.com", true], ["example.com", null, true]]) {
		assert.strictEqual(M.isStale(rp, site), stale);
		const vm = M.credentialViewModel({ rp_id: rp, enabled: 0, flagged: 1 }, { siteRpId: site });
		assert.strictEqual(vm.stale, stale);
		assert.strictEqual(vm.usable, false);
		assert.strictEqual(vm.rpId, rp);
	}
	const vm = M.credentialViewModel({ rp_id: "old.test", enabled: 1, stale: false, usable: true });
	assert.strictEqual(vm.stale, false, "wire booleans are authoritative");
	assert.strictEqual(vm.usable, true);
});

test("staleNotice prioritizes off, then stale-only, and stays absent for mixed rows", () => {
	assert.strictEqual(M.staleNotice({ site_rp_id: null, credentials: [] }), "siteOffNotice");
	assert.strictEqual(M.staleNotice({ site_rp_id: "new.test", credentials: [{ stale: true, usable: false }] }), "staleNudgeBody");
	assert.strictEqual(M.staleNotice({ site_rp_id: "new.test", credentials: [{ stale: true, usable: false }, { stale: false, usable: true }] }), null);
	assert.strictEqual(M.staleNotice({ site_rp_id: "new.test", credentials: [{ stale: false, usable: false }] }), null);
});

test("Signals skip absent payloads and an explicit off RP; response RP wins over boot", () => {
	const calls = [];
	const PKC = { signalAllAcceptedCredentials: (p) => calls.push(p), signalCurrentUserDetails: (p) => calls.push(p) };
	for (const data of [null, {}, { signal: null }, { rp_id: null, user_handle: "u", credential_ids: [], name: "user" }]) {
		assert.deepStrictEqual(M.signalCredentialState(PKC, data, "stale.boot"), { accepted: false, details: false });
	}
	assert.deepStrictEqual(calls, []);
	M.signalCredentialState(PKC, { rp_id: "current.test", user_handle: "u", credential_ids: [] }, "stale.boot");
	assert.deepStrictEqual(calls, [{ rpId: "current.test", userId: "u", allAcceptedCredentialIds: [] }]);
});
