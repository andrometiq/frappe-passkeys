// passkey_login_verify.test.js — the verify round-trip's TERMINAL CLEANUP contract.
//
// runVerify(cred) arms a slow-connection timer and paints "Verifying…", then fires
// verify_login. The named statusCode handlers only resolve the surface on 200
// (onSuccessEarly) and the TYPED passkey 401s (on401). A plain 401, a 417/429/5xx, or
// a transport/network failure hit no app handler — so before this fix the slow timer
// stayed armed and the surface stuck on "Verifying…" (escalating to the slow copy) even
// though the request had already failed. runVerify now hooks ONE always-style finalizer
// onto the frappe.call thenable: it fires once on every outcome, clears the timer, and —
// only if still stuck mid-progress — downgrades to the generic "failed" route-out, without
// ever clobbering a state a more specific handler already painted.
//
// No bench / no jsdom — a tiny hand-rolled DOM + fake timers + a frappe.call stub, loaded
// through the bundle's node seam. The node runner gives each file its own process, so the
// window/document/timer globals set here don't leak into the pure suites.
//
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");

const C = require("../../public/js/passkey_common.js");

// Keep the real timer so tests can yield a macrotask even while the bundle sees fakes.
const realSetTimeout = global.setTimeout;
const tick = () => new Promise((r) => realSetTimeout(r, 0));

// ------------------------------------------------- fake timers (installed before load)
// The bundle schedules boot() via setTimeout at load time; swallowing timers keeps boot
// from firing (no fetch/detect side effects) AND gives us a synchronous view of whether
// the slow-connection timer was armed/cleared.
const fakeTimers = new Map();
let timerSeq = 0;
global.setTimeout = function (fn) { const id = ++timerSeq; fakeTimers.set(id, fn); return id; };
global.clearTimeout = function (id) { fakeTimers.delete(id); };

// ------------------------------------------------------------- minimal DOM stub (no jsdom)
function fakeEl() {
	return {
		id: "", className: "", hidden: false, textContent: "", _attrs: {},
		setAttribute(k, v) { this._attrs[k] = v; },
		appendChild() {},
		querySelector() { return fakeEl(); },
	};
}
function makeDoc() {
	const byId = {};
	const doc = {
		readyState: "complete", // NOT "loading" -> boot takes the swallowed-setTimeout path
		activeElement: null,
		getElementById(id) { if (!byId[id]) byId[id] = fakeEl(); return byId[id]; },
		createElement() { return fakeEl(); },
		querySelector() { return null; },
		addEventListener() {}, // login_rendered / DOMContentLoaded never fire under node
		removeEventListener() {},
	};
	doc.body = { appendChild() {} };
	doc.documentElement = doc.body;
	return doc;
}

// A localStorage stub (rememberHint / postLoginUpsell touch it on the success path).
function makeStorage() {
	const m = {};
	return { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
}

// Core's login.login_handlers, matching develop (200/401/417/429/500). The bundle copies
// these into its composed statusCode map; the error painters are no-ops here (we only care
// that they DON'T clear our surface — that is exactly the bug).
function makeCoreHandlers() {
	const calls = [];
	const painter = (code) => function () { calls.push(code); };
	return {
		handlers: { 200: painter(200), 401: painter(401), 417: painter(417), 429: painter(429), 500: painter(500) },
		calls: calls,
	};
}

global.document = makeDoc();
global.navigator = {};
global.fetch = function () { return Promise.reject(new Error("no network in test")); }; // neutralise any re-arm
const core = makeCoreHandlers();
global.window = {
	frappe: { passkeys_common: C },
	login: { login_handlers: core.handlers },
	localStorage: makeStorage(),
};
global.localStorage = global.window.localStorage;

// require AFTER globals exist — the login bundle reads window at load, exposes internals
// through the node seam.
const mod = require("../../public/js/passkey_login.bundle.js");
assert.strictEqual(typeof mod.runVerify, "function", "node test seam must export runVerify");

// The bundle's frappe.call is the single dispatch point. Each test installs a scenario
// describing the server outcome; the stub invokes the composed statusCode handler exactly
// as frappe.request.call does (handler synchronously, THEN settle the thenable) and returns
// a native Promise so runVerify's `.then(finishVerify, finishVerify)` seam fires.
function installCall(scenario) {
	global.window.frappe.call = function (opts) {
		const sc = opts.statusCode || {};
		if (scenario.networkError) {
			return Promise.reject(new Error("transport failure")); // no handler runs at all
		}
		if (scenario.status === 200) {
			const h = sc[200];
			if (h) h(scenario.data); // merged[200](data)
			return Promise.resolve(scenario.data);
		}
		const xhr = { responseJSON: scenario.data || {}, status: scenario.status };
		const h = sc[scenario.status];
		if (h) h(xhr); // merged[401]/[417]/[429]/[500](xhr)
		return Promise.reject(xhr); // jqXHR rejects on HTTP error
	};
}

// Fresh surface + a live ceremony before each drive.
function primeVerify(opts) {
	opts = opts || {};
	mod.state.status = new C.LoginStatus();
	mod.state.slowTimer = null;
	mod.state.login.stateId = "sid-under-test";
	mod.state.login.options = { rpId: "example.test" };
	// Force canRearm() false so the unknown_credential path never kicks off a rebegin fetch.
	if (opts.blockRearm) mod.state.login.rearmCount = 999;
}

const fakeCred = {
	authenticatorAttachment: "platform",
	toJSON() { return { id: "cred-1", type: "public-key", response: {} }; },
};

test("verify: a transport failure with NO recognized status ends the verifying state (timer cleared, surface -> failed)", async () => {
	primeVerify();
	installCall({ networkError: true });

	mod.runVerify(fakeCred, { source: "button" });
	assert.strictEqual(mod.state.status.state, "verifying", "starts in verifying with the slow timer armed");
	assert.notStrictEqual(mod.state.slowTimer, null, "slow timer armed for the round-trip");

	await tick();

	assert.strictEqual(mod.state.status.state, "failed", "no-status transport failure downgrades to failed");
	assert.strictEqual(mod.state.slowTimer, null, "the slow-connection escalation timer is cleared");
});

test("verify: a 500 that only paints core (never touches our surface) still ends the verifying state", async () => {
	primeVerify();
	installCall({ status: 500, data: {} });

	mod.runVerify(fakeCred, { source: "button" });
	await tick();

	assert.strictEqual(mod.state.status.state, "failed", "500 no longer sticks on Verifying…");
	assert.strictEqual(mod.state.slowTimer, null, "slow timer cleared on the 5xx outcome");
	assert.ok(core.calls.includes(500), "core's own 500 painter still ran (surfaces no longer merely disagree)");
});

test("verify: a 429 throttle ends the verifying state (core painter runs, our surface routes out)", async () => {
	primeVerify();
	installCall({ status: 429, data: {} });

	mod.runVerify(fakeCred, { source: "button" });
	await tick();

	assert.strictEqual(mod.state.status.state, "failed", "429 no longer sticks on Verifying…");
	assert.strictEqual(mod.state.slowTimer, null, "slow timer cleared on the 429 outcome");
});

test("verify: the finalizer does NOT overwrite the success beat a 200 handler already painted", async () => {
	primeVerify();
	installCall({ status: 200, data: { message: "Logged In" } });

	mod.runVerify(fakeCred, { source: "button" });
	await tick();

	assert.strictEqual(mod.state.status.state, "success", "success is owned by onSuccessEarly; finalizer must not clobber it");
	assert.strictEqual(mod.state.slowTimer, null, "slow timer cleared on success");
});

test("verify: the finalizer does NOT overwrite a specific typed-401 state (removed) the on401 handler set", async () => {
	primeVerify({ blockRearm: true });
	installCall({ status: 401, data: { exc_type: "UnknownCredential" } });

	mod.runVerify(fakeCred, { source: "button" });
	await tick();

	assert.strictEqual(mod.state.status.state, "removed", "on401 owns UnknownCredential -> removed; finalizer must leave it");
	assert.strictEqual(mod.state.slowTimer, null, "slow timer cleared by on401");
});
