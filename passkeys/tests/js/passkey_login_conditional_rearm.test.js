// passkey_login_conditional_rearm.test.js — B12: the conditional-UI (autofill)
// challenge-expiry RETRY contract.
//
// A page-load login challenge has a bounded TTL (300 s). When the user returns to a
// backgrounded tab and picks a passkey from the autofill dropdown hours later, the
// conditional get() resolves and the client posts what may be a STALE challenge. The
// question B12 pins: does the conditional/autofill flow re-arm with a FRESH challenge
// after expiry, or does a stale-challenge 401 dead-end the user?
//
// Behaviour (verified here): automatic re-arms stay bounded within one failure episode,
// while a fresh adopted state resets capacity and any spent state makes the next explicit
// click await a fresh begin before opening WebAuthn. The state_id/options pair is pinned
// across the gesture, so an asynchronous adopt cannot mismatch the verify POST.
//
// Same hand-rolled DOM + fake timers + frappe.call stub as passkey_login_verify.test.js,
// loaded through the bundle's node seam. Own process per file (node:test), so the
// window/document globals set here never leak into the pure suites.
//
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");

const C = require("../../public/js/passkey_common.bundle.js");

const realSetTimeout = global.setTimeout;
const tick = () => new Promise((r) => realSetTimeout(r, 0));
const originalNavigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, "navigator");

function installNavigator(value) {
	Object.defineProperty(globalThis, "navigator", {
		configurable: true,
		enumerable: true,
		value,
		writable: true,
	});
}

test.after(() => {
	if (originalNavigatorDescriptor) {
		Object.defineProperty(globalThis, "navigator", originalNavigatorDescriptor);
	} else {
		delete globalThis.navigator;
	}
});

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
installNavigator({}); // no navigator.credentials — startConditional early-returns regardless
global.fetch = function () { return Promise.reject(new Error("no network in test")); };
const core = makeCoreHandlers();
global.window = {
	frappe: { passkeys_common: C },
	login: { login_handlers: core.handlers },
	localStorage: makeStorage(),
	addEventListener() {},
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

function beginResponse(stateId, challenge) {
	return {
		ok: true,
		json: () => Promise.resolve({
			message: {
				enabled: true,
				modes: { first_factor: true, second_factor: false },
				state_id: stateId,
				options: { rpId: "example.test", challenge },
			},
		}),
	};
}

function deferred() {
	let resolve;
	const promise = new Promise((done) => { resolve = done; });
	return { promise, resolve };
}

// Fresh surface + a STALE live ceremony + a full re-arm budget before each drive.
function primeConditional() {
	mod.state.status = new C.LoginStatus();
	mod.state.slowTimer = null;
	mod.state.login.adopt("sid-under-test", { rpId: "example.test", challenge: "AQ" });
	mod.state.login.maxRearm = 1;
	mod.state.conditionalAbort = null;
	mod.state.conditionalEnabled = true;
	mod.state.busyModal = false;
	mod.state.modes.first_factor = false;
}

const fakeCred = {
	authenticatorAttachment: "platform",
	toJSON() { return { id: "cred-1", type: "public-key", response: {} }; },
};

test("conditional expiry re-arms with a FRESH challenge (no stale-challenge dead-end)", async () => {
	primeConditional();
	const fetchCalls = installFetch({ rpId: "example.test", challenge: "fresh-challenge" });
	installCall({ status: 401, data: { exc_type: "CeremonyExpired" } });

	mod.runVerify(fakeCred, { source: "conditional" }, "sid-under-test");
	await tick();
	await tick();

	assert.strictEqual(mod.state.login.stateId, "fresh-sid", "the stale challenge was replaced by a freshly re-begun one");
	assert.strictEqual(mod.state.login.options.challenge, "fresh-challenge", "the re-armed options carry the fresh challenge");
	assert.strictEqual(fetchCalls(), 1, "exactly one re-begin fetch fired");
	assert.strictEqual(mod.state.login.rearmCount, 1, "only the successful automatic re-arm spends the budget");
	assert.notStrictEqual(mod.state.status.state, "failed", "a conditional expiry is silent — no stale-challenge failure is surfaced");
});

test("conditional expiry budget bounds automatic loops but leaves a spent state explicitly recoverable", async () => {
	primeConditional();
	mod.state.login.rearmCount = mod.state.login.maxRearm; // budget already spent
	const fetchCalls = installFetch({ rpId: "example.test", challenge: "fresh-challenge" });
	installCall({ status: 401, data: { exc_type: "CeremonyExpired" } });

	mod.runVerify(fakeCred, { source: "conditional" }, "sid-under-test");
	await tick();
	await tick();

	assert.strictEqual(fetchCalls(), 0, "no re-begin once the re-arm budget is spent (never an autofill loop)");
	assert.strictEqual(mod.state.login.stateId, "sid-under-test", "no automatic fresh challenge was adopted");
	assert.strictEqual(mod.state.login.spent, true, "the consumed state stays marked spent for click recovery");
	assert.strictEqual(mod.state.login.needsPreModalRebegin(Date.now()), true, "the next click will re-begin");
	assert.strictEqual(mod.state.status.state, "failed", "bounded: routes out to the password form instead of looping");
});

test("spent-state button click awaits re-begin before arming the WebAuthn gesture", async () => {
	primeConditional();
	mod.state.login.markSpent("sid-under-test");
	const begun = deferred();
	let fetchCalls = 0;
	global.fetch = function () { fetchCalls += 1; return begun.promise; };
	const gets = [];
	installNavigator({
		credentials: {
			get(options) { gets.push(options); return new Promise(() => {}); },
		},
	});

	mod.onButtonClick();
	assert.strictEqual(fetchCalls, 1, "click starts exactly one fresh begin");
	assert.strictEqual(gets.length, 0, "the authenticator is not opened while begin is pending");

	begun.resolve(beginResponse("fresh-click-sid", "Ag"));
	await tick();
	await tick();

	assert.strictEqual(gets.length, 1, "the gesture starts only after the fresh state is adopted");
	assert.strictEqual(mod.state.login.stateId, "fresh-click-sid");
	assert.strictEqual(gets[0].publicKey.challenge[0], 2, "the gesture uses the fresh options pair");
});

test("failed click re-begin paints unavailable and the next click retries from scratch", async () => {
	primeConditional();
	mod.state.login.markSpent("sid-under-test");
	let fetchCalls = 0;
	global.fetch = function () {
		fetchCalls += 1;
		return Promise.resolve(fetchCalls === 1 ? { ok: false } : beginResponse("recovered-sid", "Aw"));
	};
	const gets = [];
	installNavigator({
		credentials: {
			get(options) { gets.push(options); return new Promise(() => {}); },
		},
	});

	mod.onButtonClick();
	await tick();
	assert.strictEqual(gets.length, 0, "a degraded begin never spends a WebAuthn gesture");
	assert.strictEqual(mod.state.login.spent, true, "failed begin leaves the held state recoverable");
	assert.strictEqual(
		global.document.getElementById(C.LIVE_REGION_ID).textContent,
		"Passkeys aren't available right now."
	);

	mod.onButtonClick();
	await tick();
	await tick();
	assert.strictEqual(fetchCalls, 2, "the later click retries begin rather than dead-ending");
	assert.strictEqual(gets.length, 1, "the recovered click opens WebAuthn once");
	assert.strictEqual(mod.state.login.stateId, "recovered-sid");
});

test("verify POST keeps the state_id captured with options when a newer adopt lands mid-gesture", async () => {
	primeConditional();
	const credential = deferred();
	installNavigator({
		credentials: {
			get() { return credential.promise; },
		},
	});
	let posted = null;
	global.window.frappe.call = function (opts) {
		posted = opts.args;
		if (opts.statusCode && opts.statusCode[200]) opts.statusCode[200]({ message: "Logged In" });
		return Promise.resolve();
	};

	mod.onButtonClick();
	mod.state.login.adopt("async-fresh-sid", { rpId: "example.test", challenge: "BA" });
	credential.resolve(fakeCred);
	await tick();

	assert.strictEqual(posted.state_id, "sid-under-test", "POST is pinned to the state that armed get()");
	assert.strictEqual(mod.state.login.stateId, "async-fresh-sid", "the newer state remains adopted");
	assert.strictEqual(mod.state.login.spent, false, "the older gesture cannot poison the newer state");
});

test("bfcache pageshow spends the restored state and re-arms conditional UI from a fresh begin", async () => {
	primeConditional();
	mod.state.modes.first_factor = true;
	mod.state.busyModal = true;
	const begun = deferred();
	global.fetch = function () { return begun.promise; };
	installNavigator({});

	mod.onPageShow({ persisted: true });
	assert.strictEqual(mod.state.login.spent, true, "the restored page never trusts its held state");
	assert.strictEqual(mod.state.busyModal, false, "a dead pre-navigation modal cannot block the next click");

	begun.resolve(beginResponse("pageshow-sid", "BQ"));
	await tick();
	await tick();
	assert.strictEqual(mod.state.login.stateId, "pageshow-sid");
	assert.strictEqual(mod.state.login.spent, false);
});
