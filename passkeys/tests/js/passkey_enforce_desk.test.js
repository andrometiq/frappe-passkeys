// passkey_enforce_desk.test.js — the desk enforcement interstitial's DEFER-on-dismiss
// contract (grace-evasion fix).
//
// The non-blocking enforce gate must spend exactly one grace login however it closes:
// an explicit "Remind me later" click already recorded a DEFER, but before the fix an
// Esc / backdrop / close-X dismissal recorded nothing — so a capable user could press
// Esc every session and be nagged forever without grace ever being spent. The fix wires
// a `hide.bs.modal` handler (guarded by `_acted`) mirroring the sibling nudge dialog.
//
// No bench / no jsdom — a hand-rolled DOM + a mock frappe.ui.Dialog (whose .hide() fires
// the registered hide.bs.modal handlers, as Bootstrap does on any dismissal route),
// loaded through the desk bundle's node seam. Each `node --test` file gets its own
// process, so these globals never leak into the pure suites.
//
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");

const C = require("../../public/js/passkey_common.js");
const M = require("../../public/js/passkey_manage_common.js");

// Swallow load-time timers (the bundle schedules onReady via setTimeout at boot).
global.setTimeout = function () { return 0; };
global.clearTimeout = function () {};

// ------------------------------------------------------------- minimal DOM (no jsdom)
function fakeEl(tag) {
	const node = {
		tagName: String(tag || "").toUpperCase(),
		className: "", textContent: "", innerHTML: "", type: "",
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

// A mock frappe.ui.Dialog. .hide() fires the hide.bs.modal handlers registered via
// $wrapper.on — the one path every real dismissal (Esc / backdrop / X / programmatic)
// funnels through. It is intentionally NOT idempotent so a repeated hide exercises the
// bundle's own `_acted` guard rather than a mock-side dedup.
function makeDialogClass() {
	const instances = [];
	function Dialog(opts) {
		const self = this;
		this.opts = opts || {};
		this._body = fakeEl("div");
		this._wrap = {};
		this.$body = { get() { return self._body; } };
		this.$wrapper = {
			modal() {},
			attr() { return this; },
			on(type, fn) { (self._wrap[type] = self._wrap[type] || []).push(fn); return this; },
		};
		this.header = { find() { return { hide() {} }; } };
		this.shown = false; this.hidden = false;
		instances.push(this);
	}
	Dialog.prototype.show = function () { this.shown = true; };
	Dialog.prototype.hide = function () {
		this.hidden = true;
		(this._wrap["hide.bs.modal"] || []).slice().forEach((fn) => fn());
	};
	Dialog.instances = instances;
	return Dialog;
}

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

const Dialog = makeDialogClass();
const frappeObj = { passkeys_common: C, passkeys_manage_common: M, ui: { Dialog } };
global.frappe = frappeObj; // the bundle uses a bare `frappe.ui.Dialog`
global.document = (function () {
	const doc = { readyState: "complete", createElement: (tag) => fakeEl(tag), getElementById: () => null, addEventListener() {}, removeEventListener() {} };
	doc.body = fakeEl("body");
	doc.documentElement = doc.body;
	return doc;
})();
global.window = { frappe: frappeObj, localStorage: { getItem: () => null, setItem() {}, removeItem() {} } };
global.localStorage = global.window.localStorage;

const mod = require("../../public/js/passkey_desk.bundle.js");
assert.strictEqual(typeof mod.showEnforceDialog, "function", "node test seam must export showEnforceDialog");

test("desk enforce: dismissing a non-blocking gate WITHOUT acting records exactly one defer", () => {
	fetchLog.length = 0;
	Dialog.instances.length = 0;
	mod.showEnforceDialog({}, { blocking: false, graceRemaining: 2 });
	const d = Dialog.instances[Dialog.instances.length - 1];
	assert.ok(d, "a dialog was created");
	assert.strictEqual(deferCount(), 0, "opening the gate records nothing");

	d.hide(); // Esc / backdrop / close-X all fire hide.bs.modal
	assert.strictEqual(deferCount(), 1, "an unacted dismissal spends exactly one grace login");

	d.hide(); // a repeated dismissal must not double-count — the _acted guard holds
	assert.strictEqual(deferCount(), 1, "a repeated hide does not double-record");
});

test("desk enforce: the explicit 'Remind me later' records ONE defer and its follow-on hide adds none", () => {
	fetchLog.length = 0;
	Dialog.instances.length = 0;
	mod.showEnforceDialog({}, { blocking: false, graceRemaining: 3 });
	const d = Dialog.instances[Dialog.instances.length - 1];
	const link = findButton(d._body, (b) => (b.className || "").includes("btn-link"));
	assert.ok(link, "the 'Remind me later' link is present while grace remains");

	link.click(); // records DEFER, then hides — the hide handler must see _acted and no-op
	assert.strictEqual(deferCount(), 1, "exactly one defer from the explicit action (the hide handler does not double it)");
});

test("desk enforce: a blocking (grace-exhausted) gate wires no dismissal defer", () => {
	fetchLog.length = 0;
	Dialog.instances.length = 0;
	mod.showEnforceDialog({ enforcement: { incapable_policy: "degrade" } }, { blocking: true, graceRemaining: 0 });
	const d = Dialog.instances[Dialog.instances.length - 1];
	d.hide();
	assert.strictEqual(deferCount(), 0, "a blocking gate is static and has no grace left — it never records a defer");
});
