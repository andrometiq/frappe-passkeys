// passkey_login_conditional_rearm.test.js — B12: the conditional-UI (autofill)
// challenge-expiry RETRY contract.
//
// A page-load login challenge has a bounded TTL (300 s). When the user returns to a
// backgrounded tab and picks a passkey from the autofill dropdown hours later, the
// conditional get() resolves and the client posts what may be a STALE challenge. The
// question B12 pins: does the conditional/autofill flow re-arm with a FRESH challenge
// after expiry, or does a stale-challenge 401 dead-end the user?
//
// Behaviour (verified here): a ceremony_expired typed-401 on a `source: "conditional"`
// verify runs handleFirstFactor401 -> rebegin() (a fresh begin_login POST that adopts a
// new state_id + challenge) -> startConditional() (silent re-arm). It is BOUNDED by the
// CeremonyState re-arm budget (maxRearm = 1): once spent it routes out to the password
// form instead of looping. No stale-challenge error is ever surfaced to the user.
//
// Same hand-rolled DOM + fake timers + frappe.call stub as passkey_login_verify.test.js,
// loaded through the bundle's node seam. Own process per file (node:test), so the
// window/document globals set here never leak into the pure suites.
//
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");

const C = require("../../public/js/passkey_common.js");

const realSetTimeout = global.setTimeout;
const tick = () => new Promise((r) => realSetTimeout(r, 0));

// ---- fake timers (installed before load: swallow boot()'s setTimeout) ----------------
const fakeTimers = new Map();
let timerSeq = 0;
global.setTimeout = function (fn) { const id = ++timerSeq; fakeTimers.set(id, fn); return id; };
global.clearTimeout = function (id) { fakeTimers.delete(id); };

// ---- minimal DOM stub (no jsdom) — querySelector returns null so startConditional's
// re-arm early-returns after adopting the fresh state (no navigator.credentials needed).
function fakeEl() {
	return {
		id: "", className: "", hidden: false, textContent: "", _attrs: {},
		setAttribute(k, v) { this._attrs[k] = v; },
		getAttribute() { return null; },
		appendChild() {},
		querySelector() { return fakeEl(); },
	};
}
function makeDoc() {
	const byId = {};
	const doc = {
		readyState: "complete",
		activeElement: null,
		getElementById(id) { if (!byId[id]) byId[id] = fakeEl(); return byId[id]; },
		createElement() { return fakeEl(); },
		querySelector() { return null; }, // no #login_email -> conditional re-arm early-returns
		addEventListener() {},
		removeEventListener() {},
	};
	doc.body = { appendChild() {} };
	doc.documentElement = doc.body;
	return doc;
}

function makeStorage() {
	const m = {};
	return { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
}

function makeCoreHandlers() {
	const calls = [];
	const painter = (code) => function () { calls.push(code); };
	return { handlers: { 200: painter(200), 401: painter(401), 417: painter(417), 429: painter(429), 500: painter(500) }, calls };
}

global.document = makeDoc();
global.navigator = {}; // no navigator.credentials — startConditional early-returns regardless
global.fetch = function () { return Promise.reject(new Error("no network in test")); };
const core = makeCoreHandlers();
global.window = {
	frappe: { passkeys_common: C },
	login: { login_handlers: core.handlers },
	localStorage: makeStorage(),
};
global.localStorage = global.window.localStorage;

const mod = require("../../public/js/passkey_login.bundle.js");
assert.strictEqual(typeof mod.runVerify, "function", "node test seam must export runVerify");

// The verify_login dispatch stub: invoke the composed statusCode handler exactly as
// frappe.request.call does, then settle the thenable.
function installCall(scenario) {
	global.window.frappe.call = function (opts) {
		const sc = opts.statusCode || {};
		if (scenario.status === 200) { const h = sc[200]; if (h) h(scenario.data); return Promise.resolve(scenario.data); }
		const xhr = { responseJSON: scenario.data || {}, status: scenario.status };
		const h = sc[scenario.status];
		if (h) h(xhr);
		return Promise.reject(xhr);
	};
}

// The re-begin (beginLogin) fetch stub: returns a FRESH state_id + options and counts hits.
function installFetch(freshOptions) {
	let calls = 0;
	global.fetch = function () {
		calls += 1;
		return Promise.resolve({
			ok: true,
			json: () => Promise.resolve({
				message: { enabled: true, modes: { first_factor: true, second_factor: false }, state_id: "fresh-sid", options: freshOptions },
			}),
		});
	};
	return () => calls;
}

// Fresh surface + a STALE live ceremony + a full re-arm budget before each drive.
function primeConditional() {
	mod.state.status = new C.LoginStatus();
	mod.state.slowTimer = null;
	mod.state.login.stateId = "sid-under-test";
	mod.state.login.options = { rpId: "example.test", challenge: "stale-challenge" };
	mod.state.login.rearmCount = 0;
	mod.state.login.maxRearm = 1;
}

const fakeCred = {
	authenticatorAttachment: "platform",
	toJSON() { return { id: "cred-1", type: "public-key", response: {} }; },
};

test("conditional expiry re-arms with a FRESH challenge (no stale-challenge dead-end)", async () => {
	primeConditional();
	const fetchCalls = installFetch({ rpId: "example.test", challenge: "fresh-challenge" });
	installCall({ status: 401, data: { exc_type: "CeremonyExpired" } });

	mod.runVerify(fakeCred, { source: "conditional" });
	await tick();
	await tick();

	assert.strictEqual(mod.state.login.stateId, "fresh-sid", "the stale challenge was replaced by a freshly re-begun one");
	assert.strictEqual(mod.state.login.options.challenge, "fresh-challenge", "the re-armed options carry the fresh challenge");
	assert.strictEqual(fetchCalls(), 1, "exactly one re-begin fetch fired");
	assert.notStrictEqual(mod.state.status.state, "failed", "a conditional expiry is silent — no stale-challenge failure is surfaced");
});

test("conditional expiry re-arm is BOUNDED — a spent budget fails out instead of looping", async () => {
	primeConditional();
	mod.state.login.rearmCount = mod.state.login.maxRearm; // budget already spent
	const fetchCalls = installFetch({ rpId: "example.test", challenge: "fresh-challenge" });
	installCall({ status: 401, data: { exc_type: "CeremonyExpired" } });

	mod.runVerify(fakeCred, { source: "conditional" });
	await tick();
	await tick();

	assert.strictEqual(fetchCalls(), 0, "no re-begin once the re-arm budget is spent (never an autofill loop)");
	assert.strictEqual(mod.state.login.stateId, "sid-under-test", "state untouched — no fresh challenge adopted");
	assert.strictEqual(mod.state.status.state, "failed", "bounded: routes out to the password form instead of looping");
});
