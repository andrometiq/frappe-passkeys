// passkey_common.test.js — dependency-free unit harness for the pure login logic.
// Runs WITHOUT the bench and WITHOUT jsdom/eslint:  node --test passkeys/tests/js
//
// Covers: base64url round-trip, L3 options parsing (polyfill path), assertion->JSON,
// layered feature detection (getClientCapabilities absent-key = unknown, legacy fallback),
// server exc_type mapping, DOMException mapping, selector resolution (tiny DOM stub),
// the retry/re-arm state machine, and the i18n MERGE (never clobber).

const test = require("node:test");
const assert = require("node:assert");
const C = require("../../public/js/passkey_common.bundle.js");

// --------------------------------------------------------- tiny DOM stub
// Just enough of the DOM for selector-resolution + a11y helpers, no jsdom needed.
function makeEl(tag) {
	return {
		tagName: (tag || "div").toUpperCase(),
		children: [],
		attributes: {},
		style: {},
		className: "",
		id: "",
		_text: "",
		ownerDocument: null,
		get textContent() { return this._text; },
		set textContent(v) { this._text = v; },
		setAttribute(k, v) { this.attributes[k] = v; },
		getAttribute(k) { return this.attributes[k] === undefined ? null : this.attributes[k]; },
		appendChild(c) { this.children.push(c); c.parentNode = this; return c; },
		querySelector(sel) { return matchOne(this, sel); },
		querySelectorAll(sel) { return matchAll(this, sel); },
	};
}
function matchesSel(el, sel) {
	if (!el || !el.tagName) return false;
	if (sel.charAt(0) === "#") return el.id === sel.slice(1);
	if (sel.charAt(0) === ".") return (" " + el.className + " ").indexOf(" " + sel.slice(1) + " ") !== -1;
	return el.tagName === sel.toUpperCase();
}
function walk(el, fn) {
	(el.children || []).forEach(function (c) { fn(c); walk(c, fn); });
}
function matchOne(root, sel) {
	// support comma lists (first match wins, in document order)
	var sels = sel.split(",").map(function (s) { return s.trim(); });
	var found = null;
	for (var i = 0; i < sels.length && !found; i++) {
		walk(root, function (c) { if (!found && matchesSel(c, sels[i])) found = c; });
	}
	return found;
}
function matchAll(root, sel) {
	var out = [];
	walk(root, function (c) { if (matchesSel(c, sel)) out.push(c); });
	return out;
}
function makeDoc() {
	var doc = makeEl("document");
	doc.body = makeEl("body");
	doc.appendChild(doc.body);
	doc._byId = {};
	doc.createElement = function (tag) { var e = makeEl(tag); e.ownerDocument = doc; return e; };
	doc.getElementById = function (id) { return matchOne(doc, "#" + id); };
	doc.querySelector = function (sel) { return matchOne(doc, sel); };
	doc.querySelectorAll = function (sel) { return matchAll(doc, sel); };
	return doc;
}

// ------------------------------------------------------------- base64url
test("base64url round-trips arbitrary bytes (unpadded out, padded-tolerant in)", () => {
	const bytes = new Uint8Array([0, 1, 2, 250, 251, 255, 62, 63]);
	const s = C.bytesToB64url(bytes);
	assert.ok(!/=/.test(s), "encoded output is unpadded");
	assert.ok(!/[+/]/.test(s), "encoded output is url-safe");
	const back = C.b64urlToBytes(s);
	assert.deepStrictEqual(Array.from(back), Array.from(bytes));
	// tolerate a padded / standard-alphabet input too
	assert.deepStrictEqual(Array.from(C.b64urlToBytes("AAEC")), [0, 1, 2]);
});

// ------------------------------------------------- L3 options parsing (polyfill)
test("parseRequestOptionsFromJSON polyfill decodes challenge + allowCredentials, keeps hybrid", () => {
	const challenge = C.bytesToB64url(new Uint8Array([9, 8, 7]));
	const credId = C.bytesToB64url(new Uint8Array([1, 2, 3, 4]));
	const opts = C.parseRequestOptionsFromJSON({
		challenge,
		timeout: 300000,
		rpId: "example.com",
		userVerification: "preferred",
		allowCredentials: [{ type: "public-key", id: credId, transports: ["hybrid", "internal"] }],
	}, undefined /* force polyfill */);
	assert.deepStrictEqual(Array.from(new Uint8Array(opts.challenge)), [9, 8, 7]);
	assert.strictEqual(opts.timeout, 300000);
	assert.strictEqual(opts.rpId, "example.com");
	assert.strictEqual(opts.allowCredentials.length, 1);
	assert.deepStrictEqual(Array.from(new Uint8Array(opts.allowCredentials[0].id)), [1, 2, 3, 4]);
	assert.deepStrictEqual(opts.allowCredentials[0].transports, ["hybrid", "internal"], "hybrid transport survives");
});

test("parseRequestOptionsFromJSON prefers the native L3 static when present", () => {
	let called = false;
	const fakePKC = { parseRequestOptionsFromJSON(json) { called = true; return { native: true, echo: json }; } };
	const out = C.parseRequestOptionsFromJSON({ challenge: "AA" }, fakePKC);
	assert.ok(called && out.native, "native path used");
});

test("authAssertionToJSON prefers native toJSON, else builds AuthenticationResponseJSON", () => {
	assert.deepStrictEqual(C.authAssertionToJSON({ toJSON() { return { ok: 1 }; } }), { ok: 1 });
	const cred = {
		id: "abc",
		rawId: new Uint8Array([1, 2]).buffer,
		type: "public-key",
		authenticatorAttachment: "cross-platform",
		getClientExtensionResults() { return { credProps: { rk: true } }; },
		response: {
			clientDataJSON: new Uint8Array([10]).buffer,
			authenticatorData: new Uint8Array([20]).buffer,
			signature: new Uint8Array([30]).buffer,
			userHandle: new Uint8Array([40]).buffer,
		},
	};
	const j = C.authAssertionToJSON(cred);
	assert.strictEqual(j.type, "public-key");
	assert.strictEqual(j.authenticatorAttachment, "cross-platform");
	assert.strictEqual(j.clientExtensionResults.credProps.rk, true);
	assert.strictEqual(j.response.userHandle, C.bytesToB64url(new Uint8Array([40])));
});

// -------------------------------------------------- feature detection (layered)
test("detectCapabilities: getClientCapabilities absent key stays UNKNOWN (null), not false", async () => {
	const fakePKC = {
		getClientCapabilities() { return Promise.resolve({ conditionalGet: true }); }, // no UVPAA key
		isUserVerifyingPlatformAuthenticatorAvailable() { return Promise.resolve(false); },
	};
	const caps = await C.detectCapabilities({ window: { PublicKeyCredential: fakePKC } });
	assert.strictEqual(caps.supported, true);
	assert.strictEqual(caps.conditionalMediation, true);
	// present in getClientCapabilities? no -> legacy probe fills it (false here)
	assert.strictEqual(caps.uvpaa, false);
});

test("detectCapabilities: no getClientCapabilities => legacy statics; unknown left null", async () => {
	const fakePKC = {
		isConditionalMediationAvailable() { return Promise.resolve(true); },
		// no isUVPAA -> stays null (unknown)
	};
	const caps = await C.detectCapabilities({ window: { PublicKeyCredential: fakePKC } });
	assert.strictEqual(caps.conditionalMediation, true);
	assert.strictEqual(caps.uvpaa, null);
});

test("detectCapabilities: no PublicKeyCredential => unsupported", async () => {
	const caps = await C.detectCapabilities({ window: {} });
	assert.strictEqual(caps.supported, false);
});

// --------------------------------------------------------- error mapping
test("mapServerExcType matches on class name (wire exc_type), unknown delegates", () => {
	assert.strictEqual(C.mapServerExcType("CeremonyExpired"), "ceremony_expired");
	assert.strictEqual(C.mapServerExcType("UnknownCredential"), "unknown_credential");
	assert.strictEqual(C.mapServerExcType("UVSetupRequired"), "uv_setup_required");
	assert.strictEqual(C.mapServerExcType("PasskeyConfirmationRequired"), "confirmation_required");
	assert.strictEqual(C.mapServerExcType("PasskeyServedByCore"), "served_by_core");
	assert.strictEqual(C.mapServerExcType("AuthenticationError"), "unknown");
	assert.strictEqual(C.mapServerExcType(undefined), "unknown");
});

test("mapDomException maps the canonical WebAuthn rejections to fixed codes", () => {
	assert.strictEqual(C.mapDomException({ name: "NotAllowedError" }).code, "user_cancelled");
	assert.strictEqual(C.mapDomException({ name: "AbortError" }).code, "user_cancelled");
	assert.strictEqual(C.mapDomException({ name: "NotSupportedError" }).code, "not_supported");
	assert.strictEqual(C.mapDomException({ name: "SecurityError" }).code, "not_supported");
	assert.strictEqual(C.mapDomException({ name: "ConstraintError" }).code, "no_credentials");
	assert.strictEqual(C.mapDomException({ name: "WeirdError" }).code, "network");
});

// ------------------------------------------------------- selector resolution
test("resolveIdentifierInput finds #login_email across generations", () => {
	const doc = makeDoc();
	const section = doc.createElement("section");
	const input = doc.createElement("input"); input.id = "login_email";
	section.appendChild(input); doc.body.appendChild(section);
	assert.strictEqual(C.resolveIdentifierInput(doc), input);
	assert.strictEqual(C.resolveIdentifierInput(makeDoc()), null, "miss returns null (no throw)");
});

test("resolveButtonMount prefers .page-card-actions, falls back to providers then form", () => {
	// generation with .page-card-actions
	let doc = makeDoc();
	let sec = doc.createElement("section"); doc.body.appendChild(sec);
	let actions = doc.createElement("div"); actions.className = "page-card-actions"; sec.appendChild(actions);
	let m = C.resolveButtonMount(doc);
	assert.strictEqual(m.mode, "actions");
	assert.strictEqual(m.mount, actions);

	// no actions, has social buttons
	doc = makeDoc(); sec = doc.createElement("section"); doc.body.appendChild(sec);
	let social = doc.createElement("div"); social.className = "social-login-buttons"; sec.appendChild(social);
	assert.strictEqual(C.resolveButtonMount(doc).mode, "providers");

	// only a form
	doc = makeDoc(); sec = doc.createElement("section"); doc.body.appendChild(sec);
	let form = doc.createElement("form"); form.className = "form-login"; sec.appendChild(form);
	assert.strictEqual(C.resolveButtonMount(doc).mode, "form");

	// total miss -> null (skip button silently, conditional UI still works)
	doc = makeDoc(); doc.body.appendChild(doc.createElement("section"));
	assert.strictEqual(C.resolveButtonMount(doc), null);
});

// ------------------------------------------------------- retry state machine
test("CeremonyState.needsPreModalRebegin fires only when age >= TTL and a state exists", () => {
	const s = new C.CeremonyState({ stateId: "s1", options: {}, beginAt: 1000, ttlMs: 300000 });
	assert.strictEqual(s.needsPreModalRebegin(1000 + 299999), false);
	assert.strictEqual(s.needsPreModalRebegin(1000 + 300000), true);
	const empty = new C.CeremonyState({ ttlMs: 300000 });
	empty.stateId = null;
	assert.strictEqual(empty.needsPreModalRebegin(1e15), false, "no state => nothing to re-begin");
});

test("CeremonyState re-arm is bounded at one per visible failure, then refuses", () => {
	const s = new C.CeremonyState({ maxRearm: 1 });
	assert.strictEqual(s.canRearm(), true);
	s.markRearm();
	assert.strictEqual(s.canRearm(), false, "second re-arm refused (never an auto loop)");
	s.reset();
	assert.strictEqual(s.canRearm(), true, "reset re-enables after a fresh success cycle");
});

test("CeremonyState.adopt swaps in a fresh state_id + resets begin clock (never re-POST)", () => {
	const s = new C.CeremonyState({ stateId: "old", beginAt: 1, ttlMs: 10 });
	s.adopt("new", { challenge: "x" }, 5000);
	assert.strictEqual(s.stateId, "new");
	assert.strictEqual(s.beginAt, 5000);
	assert.strictEqual(s.needsPreModalRebegin(5001), false);
});

// ------------------------------------------------------------- i18n merge
test("mergeAppTranslations MERGES into frappe._messages, never clobbers existing keys", () => {
	const frappe = { _messages: { "Web Form Field": "Champ", Password: "Mot de passe" } };
	C.mergeAppTranslations(frappe, { "Sign in with a passkey": "Se connecter avec une cle" });
	assert.strictEqual(frappe._messages["Web Form Field"], "Champ", "existing Web-Form string preserved");
	assert.strictEqual(frappe._messages["Sign in with a passkey"], "Se connecter avec une cle");
	// initializes _messages if absent
	const bare = {};
	C.mergeAppTranslations(bare, { A: "1" });
	assert.strictEqual(bare._messages.A, "1");
});

test("t() returns the source string when window.__ is absent (pre-boot / node)", () => {
	assert.strictEqual(C.t("Sign in with a passkey"), "Sign in with a passkey");
});

// -------------------------------------------------------- a11y live region
test("ensureLiveRegion is idempotent and polite; announce writes text", () => {
	const doc = makeDoc();
	const r1 = C.ensureLiveRegion(doc);
	assert.strictEqual(r1.getAttribute("aria-live"), "polite");
	assert.strictEqual(r1.getAttribute("role"), "status");
	const r2 = C.ensureLiveRegion(doc);
	assert.strictEqual(r1, r2, "single region reused");
	C.announce(doc, "expired — retrying");
	assert.strictEqual(r1.textContent, "expired — retrying");
});

// ------------------------------------------------------------- version-native icons (A2)
// Native-first: prefer each Frappe version's OWN sprite symbol (develop/v16 lucide
// #icon-pencil/#icon-trash/#icon-key; v15 timeless #icon-edit/#icon-delete), and ship the
// inline lucide SVG only as the fallback — v15 has no key glyph, and a login/portal page may
// carry no sprite (or inject it after our render), in which case we degrade to inline.
function fakeDoc(presentIds) {
	const set = new Set(presentIds);
	return { getElementById(id) { return set.has(id) ? { id } : null; } };
}
function assertInline(svg, msg) {
	assert.match(svg, /^<svg /, msg + ": must be an <svg>");
	assert.ok(svg.indexOf("<use") === -1, msg + ": inline form has no <use>");
	assert.ok(svg.indexOf("stroke:currentColor") !== -1, msg + ": stroke pinned inline so v15's .icon vars can't blank it");
	assert.ok(svg.indexOf('viewBox="0 0 24 24"') !== -1, msg + ": 24x24 lucide viewBox");
}
function assertNative(svg, id, msg) {
	assert.match(svg, /^<svg /, msg + ": must be an <svg>");
	assert.ok(svg.indexOf('<use href="#' + id + '">') !== -1, msg + ": references the native #" + id + " symbol");
	assert.ok(svg.indexOf("style=") === -1, msg + ": native form pins no inline fill/stroke");
}

test("iconSvg: prefers the host version's native sprite symbol when present (develop/v16)", () => {
	// develop/v16 lucide ships all three.
	const doc = fakeDoc(["icon-pencil", "icon-trash", "icon-key"]);
	assertNative(C.iconSvg("pencil", "icon icon-sm", doc), "icon-pencil", "pencil→native");
	assertNative(C.iconSvg("trash", "icon icon-sm", doc), "icon-trash", "trash→native");
	assertNative(C.iconSvg("key", "icon icon-sm", doc), "icon-key", "key→native");
	assert.ok(C.iconSvg("pencil", "icon icon-sm", doc).indexOf('class="icon icon-sm"') !== -1, "keeps the caller's classes");
});

test("iconSvg: candidate order — pencil prefers #icon-pencil over #icon-edit", () => {
	// Both present ⇒ first candidate (#icon-pencil) wins.
	assertNative(C.iconSvg("pencil", "icon", fakeDoc(["icon-pencil", "icon-edit"])), "icon-pencil", "both present");
	assertNative(C.iconSvg("trash", "icon", fakeDoc(["icon-trash", "icon-delete"])), "icon-trash", "both present");
});

test("iconSvg: falls back to each version's second candidate (v15 timeless #icon-edit/#icon-delete)", () => {
	// v15 desk/portal DOM carries timeless #icon-edit/#icon-delete but NOT lucide names.
	const v15 = fakeDoc(["icon-edit", "icon-delete", "icon-keyboard"]);
	assertNative(C.iconSvg("pencil", "icon icon-sm", v15), "icon-edit", "v15 pencil→#icon-edit");
	assertNative(C.iconSvg("trash", "icon icon-sm", v15), "icon-delete", "v15 trash→#icon-delete");
	// v15 has NO key glyph — must NOT substitute a semantically different symbol; degrade to inline.
	assertInline(C.iconSvg("key", "icon icon-sm", v15), "v15 key→inline (no key glyph on v15)");
});

test("iconSvg: no sprite (login/portal, or sprite injected after render) ⇒ pinned inline SVG", () => {
	for (const name of ["pencil", "trash", "key"]) {
		// Empty document (no symbols present at render time).
		assertInline(C.iconSvg(name, "icon icon-sm", fakeDoc([])), name + " empty doc");
		// No document at all (e.g. node / pre-DOM) — global document is undefined here.
		const svg = C.iconSvg(name, "icon icon-sm");
		assertInline(svg, name + " no doc");
		assert.ok(svg.indexOf('class="icon icon-sm"') !== -1, "keeps the caller's classes for sizing/theming");
	}
});

test("iconSvg: unknown icon name ⇒ empty string (both branches)", () => {
	assert.strictEqual(C.iconSvg("nope", "icon"), "", "unknown, no doc ⇒ empty");
	assert.strictEqual(C.iconSvg("nope", "icon", fakeDoc(["icon-nope"])), "", "unknown name is not a candidate ⇒ empty");
});

// ------------------------------------------------ signal builders (F1)
// signalUnknownCredential needs a valid {rpId, credentialId(base64url)} — the old empty
// {} rejected with TypeError and pruned nothing. buildUnknownCredentialSignal threads the
// asserted rawId + rpId, guarding the honest row-not-found case only.

test("credentialIdB64url: prefers cred.id (already base64url), else encodes rawId", () => {
	assert.strictEqual(C.credentialIdB64url({ id: "AAECAw" }), "AAECAw");
	// rawId bytes 0,1,2,3 -> base64url "AAECAw"
	assert.strictEqual(C.credentialIdB64url({ rawId: new Uint8Array([0, 1, 2, 3]) }), "AAECAw");
	assert.strictEqual(C.credentialIdB64url({}), null);
	assert.strictEqual(C.credentialIdB64url(null), null);
});

test("buildUnknownCredentialSignal: threads {rpId, credentialId} when the assertion has a userHandle", () => {
	const cred = { id: "Cred123", response: { userHandle: "dXNlcg" } };
	assert.deepStrictEqual(
		C.buildUnknownCredentialSignal(cred, "example.com"),
		{ rpId: "example.com", credentialId: "Cred123" }
	);
	// live-credential shape: ArrayBuffer-ish userHandle + rawId
	const live = { rawId: new Uint8Array([9, 9]), response: { userHandle: new Uint8Array([1]) } };
	const built = C.buildUnknownCredentialSignal(live, "example.com");
	assert.strictEqual(built.rpId, "example.com");
	assert.ok(built.credentialId && built.credentialId.length > 0);
});

test("buildUnknownCredentialSignal: skips honestly — no rpId, no cred, or NO userHandle (don't hide a live passkey)", () => {
	const cred = { id: "Cred123", response: { userHandle: "dXNlcg" } };
	assert.strictEqual(C.buildUnknownCredentialSignal(cred, ""), null, "no rpId ⇒ skip");
	assert.strictEqual(C.buildUnknownCredentialSignal(null, "example.com"), null, "no cred ⇒ skip");
	// missing userHandle ⇒ the server's UnknownCredential may be the not-a-handle branch,
	// where the credential could still be live — never signal it unknown.
	assert.strictEqual(
		C.buildUnknownCredentialSignal({ id: "Cred123", response: { userHandle: null } }, "example.com"),
		null,
		"missing userHandle ⇒ skip"
	);
	assert.strictEqual(
		C.buildUnknownCredentialSignal({ id: "Cred123", response: { userHandle: "" } }, "example.com"),
		null,
		"empty-string userHandle ⇒ skip"
	);
	// no credentialId at all (neither id nor rawId) ⇒ nothing to signal
	assert.strictEqual(
		C.buildUnknownCredentialSignal({ response: { userHandle: "dXNlcg" } }, "example.com"),
		null,
		"no credentialId ⇒ skip"
	);
});
