// passkey_login_second_factor.test.js — the second-factor dialog's failure paths.
//
// setDialogError paints the dialog's alert AND announces it, so a failure must reach the
// live region exactly once (a second announce() made screen readers hear it twice), and a
// failed verify must release the ceremony so the user can retry.
//
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");

const C = require("../../public/js/passkey_common.bundle.js");

const realSetTimeout = global.setTimeout;
const tick = () => new Promise((resolve) => realSetTimeout(resolve, 0));
// Swallow the bundle's boot timer and the dialog's deferred focus.
global.setTimeout = function () { return 0; };
global.clearTimeout = function () {};

// Minimal DOM: querySelector returns one stable child per selector, and buttons keep
// their click listeners.
function fakeEl(tag) {
	const children = {};
	const node = {
		tagName: String(tag || "").toUpperCase(),
		className: "", textContent: "", innerHTML: "", type: "", parentNode: null,
		_attrs: {}, _listeners: {}, appended: [],
		setAttribute(k, v) { node._attrs[k] = v; },
		appendChild(child) { child.parentNode = node; node.appended.push(child); return child; },
		removeChild(child) { child.parentNode = null; return child; },
		addEventListener(type, fn) { (node._listeners[type] = node._listeners[type] || []).push(fn); },
		click() { (node._listeners.click || []).forEach((fn) => fn({})); },
		contains() { return false; },
		focus() {},
		querySelector(sel) { return (children[sel] = children[sel] || fakeEl("div")); },
		querySelectorAll() { return []; },
	};
	return node;
}

const announced = [];
const common = Object.assign({}, C, { announce(doc, msg) { announced.push(msg); } });

global.document = {
	readyState: "complete", activeElement: null,
	createElement: (tag) => fakeEl(tag),
	getElementById: () => null,
	querySelector: () => null,
	addEventListener() {}, removeEventListener() {},
	body: fakeEl("body"),
};
global.document.documentElement = global.document.body;
global.window = { frappe: { passkeys_common: common }, login: { login_handlers: {} }, addEventListener() {} };

const mod = require("../../public/js/passkey_login.bundle.js");

function lastDialog() {
	const overlay = global.document.body.appended[global.document.body.appended.length - 1];
	const root = overlay.appended[0];
	const buttons = root.querySelector(".passkey-dialog-actions").appended;
	return { root, primary: buttons.find((b) => b.className.includes("btn-primary")) };
}

function install({ credentialsGet, call }) {
	global.window.PublicKeyCredential = function () {};
	Object.defineProperty(global, "navigator", {
		value: { credentials: { get: credentialsGet } },
		configurable: true, writable: true,
	});
	global.window.frappe.call = call;
}

const OPTIONS = { challenge: "AAAA", allowCredentials: [] };
const VERIFY_FAILED = "That passkey couldn't be verified — try again.";

test("second factor: a verify with no recognised status shows and announces the error once, then allows a retry", async () => {
	let verifyCalls = 0;
	install({
		credentialsGet: () => Promise.resolve({ toJSON: () => ({ id: "cred-1" }) }),
		call: () => { verifyCalls += 1; return Promise.reject(new Error("transport failure")); },
	});
	mod.runSecondFactorCeremony("state-1", OPTIONS, false);
	const { root, primary } = lastDialog();

	announced.length = 0;
	primary.click();
	await tick(); await tick(); await tick();
	assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, VERIFY_FAILED);
	assert.strictEqual(announced.filter((m) => m === VERIFY_FAILED).length, 1, "announced exactly once");

	primary.click();
	await tick(); await tick(); await tick();
	assert.strictEqual(verifyCalls, 2, "the ceremony was released, so the retry reaches the server");
});

test("second factor: a cancelled passkey prompt is announced once", async () => {
	install({
		credentialsGet: () => { const e = new Error("cancelled"); e.name = "NotAllowedError"; return Promise.reject(e); },
		call: () => assert.fail("no verify call after a cancelled prompt"),
	});
	mod.runSecondFactorCeremony("state-2", OPTIONS, false);
	const { root, primary } = lastDialog();

	announced.length = 0;
	primary.click();
	await tick(); await tick();
	const message = root.querySelector(".passkey-dialog-error").textContent;
	assert.ok(message, "the error is painted in the dialog");
	assert.strictEqual(announced.filter((m) => m === message).length, 1, "announced exactly once");
});

test("second factor: an expired ceremony adopts the server's re-armed state for the retry", async () => {
	const states = [];
	install({
		credentialsGet: () => Promise.resolve({ toJSON: () => ({ id: "cred-1" }) }),
		call: (opts) => {
			states.push(opts.args.state_id);
			if (states.length > 1) return Promise.resolve({});
			const body = { exc_type: "CeremonyExpired", state_id: "fresh-state", verification: { options: OPTIONS } };
			opts.statusCode[401]({ responseJSON: body });
			return Promise.reject(body);
		},
	});
	mod.runSecondFactorCeremony("stale-state", OPTIONS, false);
	const { root, primary } = lastDialog();
	primary.click();
	await tick(); await tick(); await tick();
	assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, "That didn't work — try your passkey again.");
	primary.click();
	await tick(); await tick(); await tick();
	assert.deepStrictEqual(states, ["stale-state", "fresh-state"]);
});
