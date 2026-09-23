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

const C = require("../../public/js/passkey_common.bundle.js");
const M = require("../../public/js/passkey_manage_common.bundle.js");

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
global.location = { hostname: "example.com" };

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

const tick = () => new Promise((resolve) => setImmediate(resolve));
const normalFetch = global.fetch;
function shownCount() { return fetchLog.filter((f) => f.body.event === M.NUDGE_EVENTS.SHOWN).length; }

test("desk nudge: SHOWN follows show, and a constructor failure spends nothing", () => {
	fetchLog.length = 0;
	global.fetch = (url, opts) => {
		assert.strictEqual(Dialog.instances.at(-1).shown, true);
		return normalFetch(url, opts);
	};
	try {
		mod.showNudgeDialog({}, false);
		assert.strictEqual(shownCount(), 1);
		frappeObj.ui.Dialog = function () { throw new Error("render failed"); };
		assert.throws(() => mod.showNudgeDialog({}, false), /render failed/);
		assert.strictEqual(shownCount(), 1);
	} finally { frappeObj.ui.Dialog = Dialog; global.fetch = normalFetch; }
});

function findClass(root, cls) {
	if (!root) return null;
	if ((root.className || "").includes(cls)) return root;
	for (const c of root.children) { const f = findClass(c, cls); if (f) return f; }
	return null;
}

test("desk opt-out keeps the dialog until saved; a failure shows a visible alert and stays retryable", async () => {
	try {
		for (const outcome of [true, false, "reject"]) {
			let settle = () => {};
			global.fetch = (url, opts) => {
				let body = {};
				try { body = JSON.parse(opts.body); } catch (e) { /* ignore */ }
				if (body.event !== M.NUDGE_EVENTS.OPT_OUT) return normalFetch(url, opts);
				return new Promise((resolve, reject) => {
					settle = () => outcome === "reject" ? reject(new Error("offline")) :
						resolve({ ok: outcome, status: outcome ? 200 : 500, json: () => Promise.resolve({}) });
				});
			};
			mod.showNudgeDialog({}, false);
			const d = Dialog.instances.at(-1);
			const never = findButton(d._body, (b) => b.textContent === M.COPY.nudgeNever);
			never.click();
			assert.strictEqual(d.hidden, false, "dialog stays while the opt-out is in flight");
			settle();
			await tick();
			if (outcome === true) { assert.strictEqual(d.hidden, true); continue; }
			assert.strictEqual(d.hidden, false, "dialog stays after a failed opt-out");
			const error = findClass(d._body, "passkey-nudge-error");
			assert.strictEqual(error.getAttribute("role"), "alert");
			assert.strictEqual(error.textContent, M.COPY.nudgeSaveFailed);
			global.fetch = normalFetch;
			never.click(); // retry succeeds
			await tick();
			assert.strictEqual(d.hidden, true, "retry closes the dialog");
		}
	} finally { global.fetch = normalFetch; }
});

test("desk upsell: consumes the flag even when server cadence caps it", async () => {
	let flag = "1";
	const storage = global.localStorage;
	global.localStorage = window.localStorage = {
		getItem: (key) => key === M.UPSELL_FLAG_KEY ? flag : null,
		removeItem: (key) => { if (key === M.UPSELL_FLAG_KEY) flag = null; },
	};
	frappeObj.boot = { passkeys: { upsell_eligible: false, nudge_state: { eligible: false } } };
	Dialog.instances.length = 0;
	try {
		mod.maybeNudge();
		await tick();
		assert.strictEqual(flag, null);
		assert.strictEqual(Dialog.instances.length, 0);
	} finally { global.localStorage = window.localStorage = storage; delete frappeObj.boot; }
});

test("desk capped Degrade falls through without showing any prompt", async () => {
	frappeObj.boot = { passkeys: {
		credential_count: 0, nudge_state: { eligible: false }, upsell_eligible: false,
		enforcement: { effective: "enforce", in_scope: true, incapable_policy: "degrade", degrade_nudge_eligible: false },
	} };
	Dialog.instances.length = 0;
	fetchLog.length = 0;
	mod.maybeNudge();
	await tick();
	assert.strictEqual(Dialog.instances.length, 0);
	assert.strictEqual(shownCount(), 0);
	delete frappeObj.boot;
});

test("desk conditional create: unsuccessful attempts fall back once, abort and credentials do not", async () => {
	window.PublicKeyCredential = {
		getClientCapabilities: () => Promise.resolve({ conditionalCreate: true }),
		parseCreationOptionsFromJSON: (options) => { if (!options) throw new Error("invalid options"); return options; },
	};
	frappeObj.boot = { passkeys: {
		nudge_state: { eligible: true }, upsell_eligible: false,
		conditional_create: true, post_login_method: "password",
	} };
	try {
		for (const outcome of ["NotAllowedError", "AbortError", "credential", "null", "begin_failed", "bad_options", "network", "verify_failed", "verify_network"]) {
			Dialog.instances.length = 0;
			fetchLog.length = 0;
			global.navigator = { credentials: { create: () => {
				if (["credential", "verify_failed", "verify_network"].includes(outcome)) return Promise.resolve({ toJSON: () => ({ id: "created" }) });
				if (outcome === "null") return Promise.resolve(null);
				return Promise.reject(Object.assign(new Error(outcome), { name: outcome }));
			} } };
			global.fetch = (url, opts) => {
				if (url.includes("begin_registration")) {
					if (outcome === "network") return Promise.reject(new Error("offline"));
					return Promise.resolve({ ok: outcome !== "begin_failed", json: () => Promise.resolve({ message: {
						options: outcome === "bad_options" ? null : {}, state_id: "state",
					} }) });
				}
				if (url.includes("verify_registration") && outcome === "verify_network") return Promise.reject(new Error("offline"));
				if (url.includes("verify_registration") && outcome === "verify_failed") {
					return Promise.resolve({ ok: false, status: 417, json: () => Promise.resolve({}) });
				}
				if (url.includes("record_nudge")) assert.strictEqual(Dialog.instances.at(-1).shown, true);
				return normalFetch(url, opts);
			};
			let dialogsWhenEvaluated = null;
			document.documentElement.setAttribute = (k) => {
				if (k === "data-passkeys-nudge-evaluated") dialogsWhenEvaluated = Dialog.instances.length;
			};
			await mod.maybeNudge();
			const expected = ["AbortError", "credential"].includes(outcome) ? 0 : 1;
			assert.strictEqual(Dialog.instances.length, expected, outcome);
			assert.strictEqual(shownCount(), expected, outcome);
			assert.strictEqual(dialogsWhenEvaluated, expected, "evaluated marker waits for the fallback: " + outcome);
			if (outcome === "credential") assert.ok(fetchLog.some((f) => f.url.includes("verify_registration")));
		}
	} finally { global.fetch = normalFetch; delete window.PublicKeyCredential; delete frappeObj.boot; }
});

test("desk conditional create: a throwing fallback is contained and still marks evaluation", async () => {
	window.PublicKeyCredential = { getClientCapabilities: () => Promise.resolve({ conditionalCreate: true }) };
	frappeObj.boot = { passkeys: {
		nudge_state: { eligible: true }, upsell_eligible: false,
		conditional_create: true, post_login_method: "password",
	} };
	global.fetch = () => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) }); // begin fails
	frappeObj.ui.Dialog = function () { throw new Error("render failed"); };
	let evaluated = false;
	document.documentElement.setAttribute = (k) => { if (k === "data-passkeys-nudge-evaluated") evaluated = true; };
	try {
		await mod.maybeNudge(); // resolves: no unhandled rejection
		assert.strictEqual(evaluated, true);
	} finally {
		frappeObj.ui.Dialog = Dialog; global.fetch = normalFetch;
		delete window.PublicKeyCredential; delete frappeObj.boot;
	}
});
