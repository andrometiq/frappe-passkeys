// passkey_enforce_portal.test.js — the portal enforcement interstitial's DEFER-on-Esc
// contract (grace-evasion fix, portal twin of passkey_enforce_desk.test.js).
//
// The portal builds its own modal (no frappe.ui.Dialog). A non-blocking enforce gate
// honors Esc (the engine calls close() when !cfg.static); before the fix showEnforceModal
// passed no onClose, so an Esc dismissal closed the gate without spending grace. The fix
// passes an onClose that records a DEFER once (guarded by `_settled`), mirroring the
// confirm modal.
//
// No bench / no jsdom — a hand-rolled document whose keydown listeners can be dispatched
// (to simulate Esc) + a fetch probe, loaded through the portal bundle's node seam.
//
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");

const C = require("../../public/js/passkey_common.js");
const M = require("../../public/js/passkey_manage_common.js");

// Swallow the focus setTimeout buildModal.open() schedules.
global.setTimeout = function () { return 0; };
global.clearTimeout = function () {};

// ------------------------------------------------------------- minimal DOM (no jsdom)
function fakeEl(tag) {
	const node = {
		tagName: String(tag || "").toUpperCase(),
		id: "", className: "", textContent: "", innerHTML: "", type: "",
		_attrs: {}, _listeners: {}, children: [], parentNode: null,
		setAttribute(k, v) { node._attrs[k] = v; },
		getAttribute(k) { return node._attrs[k]; },
		appendChild(c) { c.parentNode = node; node.children.push(c); return c; },
		removeChild(c) { const i = node.children.indexOf(c); if (i >= 0) node.children.splice(i, 1); c.parentNode = null; return c; },
		addEventListener(type, fn) { (node._listeners[type] = node._listeners[type] || []).push(fn); },
		removeEventListener(type, fn) { const a = node._listeners[type]; if (a) { const i = a.indexOf(fn); if (i >= 0) a.splice(i, 1); } },
		dispatch(type, ev) { (node._listeners[type] || []).slice().forEach((fn) => fn(ev || {})); },
		click() { node.dispatch("click", {}); },
		focus() {},
		querySelector() { return null; },
		querySelectorAll() { return []; },
	};
	return node;
}
function findButton(root, pred) {
	if (!root) return null;
	if (root.tagName === "BUTTON" && pred(root)) return root;
	for (const c of root.children) { const f = findButton(c, pred); if (f) return f; }
	return null;
}
function makeDoc() {
	const keydown = [];
	const doc = {
		activeElement: null,
		createElement: (tag) => fakeEl(tag),
		getElementById: () => null,
		querySelector: () => null,
		addEventListener(type, fn) { if (type === "keydown") keydown.push(fn); },
		removeEventListener(type, fn) { if (type === "keydown") { const i = keydown.indexOf(fn); if (i >= 0) keydown.splice(i, 1); } },
		_keydown(ev) { keydown.slice().forEach((fn) => fn(ev)); },
	};
	doc.body = fakeEl("body");
	doc.documentElement = doc.body;
	return doc;
}
function pressEscape() { global.document._keydown({ key: "Escape", preventDefault() {} }); }

// ------------------------------------------------------------ record-enforcement probe
const fetchLog = [];
global.fetch = function (url, opts) {
	let body = {};
	try { body = JSON.parse((opts && opts.body) || "{}"); } catch (e) { /* ignore */ }
	fetchLog.push({ url: String(url), body });
	return Promise.resolve({ ok: true, status: 200, json() { return Promise.resolve({ message: {} }); } });
};
function deferCount() {
	return fetchLog.filter((f) => f.url.includes("record_enforcement") && f.body.event === M.ENFORCE_EVENTS.DEFER).length;
}

const frappeObj = { passkeys_common: C, passkeys_manage_common: M };
global.frappe = frappeObj;
global.window = { frappe: frappeObj };
global.document = makeDoc(); // require-time document (mountRoot probe → null)

const mod = require("../../public/js/passkey_portal.bundle.js");
assert.strictEqual(typeof mod.showEnforceModal, "function", "node test seam must export showEnforceModal");

test("portal enforce: Esc on a non-blocking gate records exactly one defer", () => {
	fetchLog.length = 0;
	global.document = makeDoc(); // the bundle reads `document` as a bare global at call time
	mod.showEnforceModal({}, { blocking: false, graceRemaining: 2 });
	assert.strictEqual(deferCount(), 0, "opening the gate records nothing");

	pressEscape();
	assert.strictEqual(deferCount(), 1, "an Esc dismissal spends exactly one grace login");

	pressEscape(); // listener removed on close + _settled guard — no double
	assert.strictEqual(deferCount(), 1, "a repeated Esc does not double-record");
});

test("portal enforce: the explicit 'Remind me later' records ONE defer and its follow-on close adds none", () => {
	fetchLog.length = 0;
	global.document = makeDoc();
	mod.showEnforceModal({}, { blocking: false, graceRemaining: 3 });
	const overlay = global.document.body.children[global.document.body.children.length - 1];
	const link = findButton(overlay, (b) => (b.className || "").includes("btn-link"));
	assert.ok(link, "the 'Remind me later' link is present while grace remains");

	link.click(); // records DEFER, sets _settled, closes — onClose must see _settled and no-op
	assert.strictEqual(deferCount(), 1, "exactly one defer from the explicit action (onClose does not double it)");
});

test("portal enforce: a blocking (static) gate cannot be Esc-dismissed and records no defer", () => {
	fetchLog.length = 0;
	global.document = makeDoc();
	mod.showEnforceModal({ enforcement: { incapable_policy: "degrade" } }, { blocking: true, graceRemaining: 0 });
	pressEscape();
	assert.strictEqual(deferCount(), 0, "a static blocking gate suppresses Esc and records no defer");
});
