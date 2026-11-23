// passkey_login_immediate.test.js — the "Sign in with a passkey" button's immediate UI mode
// (Chrome 149+, `uiMode: "immediate"`).
//
// A browser that reports `immediateGet` gets this device's passkeys first, once per page. A
// NotAllowedError within a second means the browser had none to show (Chrome gives up after
// 500 ms), so the full sheet opens in the same click on the same ceremony; a later one means
// the user closed the picker, which gets no second sheet. Every other browser makes today's
// call unchanged.
//
// Hand-rolled DOM + fake timers + stubbed navigator.credentials / fetch / frappe.call, loaded
// through the bundle's node seam (own process per file under node:test).
//
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");

const C = require("../../public/js/passkey_common.bundle.js");

const realSetTimeout = global.setTimeout;
const realDateNow = Date.now;
const tick = () => new Promise((resolve) => realSetTimeout(resolve, 0));

// Fake timers, installed before load: boot()'s setTimeout is held here and run by the first test.
const timers = [];
global.setTimeout = function (fn) { timers.push(fn); return timers.length; };
global.clearTimeout = function () {};

// No login form: conditional UI and the button mount are skipped; status text still reaches the
// live region.
function fakeEl() {
	return {
		id: "", className: "", hidden: false, textContent: "", _attrs: {},
		setAttribute(k, v) { this._attrs[k] = v; },
		getAttribute() { return null; },
		appendChild() {},
		querySelector() { return fakeEl(); },
	};
}
const byId = {};
global.document = {
	readyState: "complete",
	activeElement: null,
	getElementById(id) { if (!byId[id]) byId[id] = fakeEl(); return byId[id]; },
	createElement() { return fakeEl(); },
	querySelector() { return null; },
	querySelectorAll() { return []; },
	addEventListener() {},
	removeEventListener() {},
};
global.document.body = { appendChild() {} };
global.document.documentElement = Object.assign(global.document.body, { lang: "en", setAttribute() {} });

const OPTIONS = { rpId: "example.test", challenge: "AQ", allowCredentials: [] };
let fetchCalls = 0;
global.fetch = function () {
	fetchCalls += 1;
	return Promise.resolve({
		ok: true,
		json: () => Promise.resolve({
			message: { enabled: true, modes: { first_factor: true, second_factor: false }, state_id: "begin-" + fetchCalls, options: OPTIONS },
		}),
	});
};
global.window = {
	frappe: { passkeys_common: C, call() { return new Promise(() => {}); } },
	login: { login_handlers: {} },
	addEventListener() {},
	PublicKeyCredential: { getClientCapabilities: () => Promise.resolve({ conditionalGet: false, immediateGet: true }) },
};

let gets = [];
function installGet(answer) {
	gets = [];
	Object.defineProperty(globalThis, "navigator", {
		configurable: true, writable: true,
		value: { credentials: { get(options) { gets.push(options); return answer(options, gets.length); } } },
	});
}
installGet(() => new Promise(() => {}));

const mod = require("../../public/js/passkey_login.bundle.js");

function notAllowed() { return new DOMException("not allowed", "NotAllowedError"); }
function liveRegion() { return global.document.getElementById(C.LIVE_REGION_ID).textContent; }
const CANCELLED = C.LOGIN_STATES.cancelled.text;

function prime(isImmediate) {
	Date.now = realDateNow;
	mod.state.status = new C.LoginStatus();
	mod.state.busyModal = false;
	mod.state.rebeginInFlight = null;
	mod.state.conditionalEnabled = false;
	mod.state.immediateGet = isImmediate;
	mod.state.login.adopt("sid-1", OPTIONS);
	fetchCalls = 0;
}

test.after(() => { Date.now = realDateNow; });

test("a browser reporting immediateGet asks for this device's passkeys first", async () => {
	timers.splice(0).forEach((fn) => fn()); // boot: detect -> begin_login -> start
	for (let i = 0; i < 8; i++) await tick();
	assert.strictEqual(mod.state.immediateGet, true, "getClientCapabilities().immediateGet was read");

	installGet(() => new Promise(() => {}));
	mod.onButtonClick();
	assert.strictEqual(gets.length, 1);
	assert.strictEqual(gets[0].uiMode, "immediate");
	assert.strictEqual(gets[0].mediation, undefined);
	assert.deepStrictEqual(gets[0].publicKey.allowCredentials, [], "immediate mode needs an empty allow list");
});

test("no passkey on this device: a quick rejection opens the full sheet in the same click, on the same ceremony", async () => {
	prime(true);
	installGet((options, n) => (n === 1 ? Promise.reject(notAllowed()) : new Promise(() => {})));

	mod.onButtonClick();
	await tick();
	await tick();
	assert.strictEqual(gets.length, 2, "the full sheet followed");
	assert.strictEqual(gets[1].uiMode, undefined, "the second request is today's full sheet");
	assert.strictEqual(gets[1].publicKey, gets[0].publicKey, "same challenge");
	assert.strictEqual(fetchCalls, 0, "no new begin_login");
	assert.strictEqual(mod.state.login.spent, false, "the ceremony is still live for the full sheet");
	assert.strictEqual(mod.state.busyModal, true, "the full sheet is open");
	assert.notStrictEqual(liveRegion(), CANCELLED, "no failure shown");
});

test("a picker the user closed (rejection after a second) opens no second sheet", async () => {
	prime(true);
	let now = 50000;
	Date.now = () => now;
	let dismiss;
	installGet(() => new Promise((resolve, reject) => { dismiss = reject; }));

	mod.onButtonClick();
	now += 1500; // the picker was on screen, then closed
	dismiss(notAllowed());
	await tick();
	await tick();
	assert.strictEqual(gets[0].uiMode, "immediate");
	assert.strictEqual(gets.length, 1, "no full sheet after a dismissal");
	assert.strictEqual(liveRegion(), CANCELLED, "the same note as closing today's sheet");
	assert.strictEqual(fetchCalls, 1, "the next ceremony is prepared");
	await tick();
	await tick();
	assert.strictEqual(mod.state.login.stateId, "begin-1", "the closed picker's ceremony was replaced");

	mod.onButtonClick();
	assert.strictEqual(gets.length, 2);
	assert.strictEqual(gets[1].uiMode, undefined, "immediate mode is tried once per page: the next click is the full sheet");
});

test("an immediate-mode error other than NotAllowedError opens no second sheet", async () => {
	prime(true);
	installGet(() => Promise.reject(new DOMException("pending", "OperationError")));
	mod.onButtonClick();
	await tick();
	await tick();
	assert.strictEqual(gets[0].uiMode, "immediate");
	assert.strictEqual(gets.length, 1);
	assert.strictEqual(mod.state.status.state, "failed");
});

test("other browsers: the click makes today's call unchanged", async () => {
	prime(false);
	installGet(() => new Promise(() => {}));
	mod.onButtonClick();
	assert.strictEqual(gets.length, 1);
	assert.deepStrictEqual(Object.keys(gets[0]), ["publicKey"]);
});
