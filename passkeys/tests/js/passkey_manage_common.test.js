// passkey_manage_common.test.js — dependency-free unit harness for the PURE
// credential-management + nudge + settings logic in
// passkey_manage_common.js. Runs WITHOUT the bench and WITHOUT jsdom:
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
const M = require("../../public/js/passkey_manage_common.js");

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

// ---------------------------------------------------------- delete guard

test("deleteGuard: last enabled credential of a passkey-only user is blocked", () => {
	assert.strictEqual(
		M.deleteGuard({ enabled: 1 }, { enabledCount: 1, passkeyOnly: 1 }).blocked,
		true
	);
	assert.strictEqual(
		M.deleteGuard({ enabled: 1 }, { enabledCount: 1, disablePassLogin: 1 }).blocked,
		true
	);
	// another enabled credential survives => allowed
	assert.strictEqual(M.deleteGuard({ enabled: 1 }, { enabledCount: 2, passkeyOnly: 1 }).blocked, false);
	// soft-disabled credential is never a login method => allowed
	assert.strictEqual(M.deleteGuard({ enabled: 0 }, { enabledCount: 1, passkeyOnly: 1 }).blocked, false);
	// ordinary account (passwords on) => allowed
	assert.strictEqual(M.deleteGuard({ enabled: 1 }, { enabledCount: 1 }).blocked, false);
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
