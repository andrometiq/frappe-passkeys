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

const C = require("../../public/js/passkey_common.bundle.js");
const M = require("../../public/js/passkey_manage_common.bundle.js");

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
		insertBefore(c, before) { c.parentNode = node; const i = node.children.indexOf(before); node.children.splice(i < 0 ? 0 : i, 0, c); return c; },
		remove() { if (node.parentNode) node.parentNode.removeChild(node); },
		removeChild(c) { const i = node.children.indexOf(c); if (i >= 0) node.children.splice(i, 1); c.parentNode = null; return c; },
		addEventListener(type, fn) { (node._listeners[type] = node._listeners[type] || []).push(fn); },
		removeEventListener(type, fn) { const a = node._listeners[type]; if (a) { const i = a.indexOf(fn); if (i >= 0) a.splice(i, 1); } },
		dispatch(type, ev) { (node._listeners[type] || []).slice().forEach((fn) => fn(ev || {})); },
		click() { node.dispatch("click", {}); },
		classList: { add(c) { node.className += " " + c; } },
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
function findNode(root, pred) {
	if (!root) return null;
	if (pred(root)) return root;
	for (const c of root.children) { const f = findNode(c, pred); if (f) return f; }
	return null;
}
function findLastNode(root, pred) {
	if (!root) return null;
	for (let i = root.children.length - 1; i >= 0; i -= 1) {
		const f = findLastNode(root.children[i], pred);
		if (f) return f;
	}
	return pred(root) ? root : null;
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
assert.strictEqual(typeof mod.makeConfirmUI, "function", "node test seam must export makeConfirmUI");

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

test("portal enforce: the blocking gate's escape is labelled by what it does under each policy", () => {
	const labels = [M.COPY.enforceCantSetUp, M.COPY.enforceContactAdmin];
	const incapable = () => fetchLog.filter((f) => f.body.event === M.ENFORCE_EVENTS.INCAPABLE).length;
	fetchLog.length = 0;

	global.document = makeDoc();
	mod.showEnforceModal({ enforcement: { incapable_policy: "degrade" } }, { blocking: true, graceRemaining: 0 });
	const cantSetUp = findButton(global.document.body, (b) => labels.includes(b.textContent));
	assert.strictEqual(cantSetUp.textContent, M.COPY.enforceCantSetUp, "Degrade notifies nobody, so it must not promise an admin");
	cantSetUp.click();
	assert.strictEqual(global.document.body.children.length, 0, "under Degrade the escape lets the user through");
	assert.strictEqual(incapable(), 1, "the incapable claim is still recorded");

	global.document = makeDoc();
	mod.showEnforceModal({ enforcement: { incapable_policy: "block_notify" } }, { blocking: true, graceRemaining: 0 });
	const contact = findButton(global.document.body, (b) => labels.includes(b.textContent));
	assert.strictEqual(contact.textContent, M.COPY.enforceContactAdmin);
	contact.click();
	assert.strictEqual(global.document.body.children.length, 1, "Block + Notify Admin keeps the gate up");
	assert.ok(findNode(global.document.body, (n) => n.textContent === M.COPY.enforceBlockedNotice), "the admin-notified notice is shown");
});

test("portal confirm: direct password route opens and Esc rejects instead of hanging", async () => {
	global.document = makeDoc();
	const ui = mod.makeConfirmUI();
	const pending = ui.collectPassword({ action: "myapp.pay", actionLabel: "Pay invoice" });
	assert.strictEqual(global.document.body.children.length, 1, "password-only route must open its modal");
	const overlay = global.document.body.children[0];
	assert.ok(findNode(overlay, (n) => n.id === "passkey-portal-pw"), "password input is visible");
	pressEscape();
	await assert.rejects(pending, (err) => err.code === C.CONFIRM_CODES.USER_CANCELLED);
});

test("portal confirm: password error remains visible on the retry prompt", async () => {
	global.document = makeDoc();
	const ui = mod.makeConfirmUI();
	const first = ui.collectPassword({ action: "myapp.pay", actionLabel: "Pay invoice" });
	let overlay = global.document.body.children[0];
	const input = findNode(overlay, (n) => n.id === "passkey-portal-pw");
	input.value = "wrong";
	findButton(overlay, (b) => (b.className || "").includes("btn-primary")).click();
	assert.strictEqual(await first, "wrong");

	ui.passwordError("That password wasn't right. Try again.");
	const retry = ui.collectPassword({ action: "myapp.pay", actionLabel: "Pay invoice" });
	overlay = global.document.body.children[0];
	const error = findLastNode(overlay, (n) => (n.className || "").includes("passkey-confirm-msg"));
	assert.strictEqual(error.textContent, "That password wasn't right. Try again.");
	pressEscape();
	await assert.rejects(retry, (err) => err.code === C.CONFIRM_CODES.USER_CANCELLED);
});

const tick = () => new Promise((resolve) => setImmediate(resolve));
const normalFetch = global.fetch;
function bannerDoc() {
	const doc = makeDoc();
	doc.querySelector = () => doc.body;
	doc.getElementById = (id) => findNode(doc.body, (n) => n.id === id);
	return doc;
}

test("portal nudge: SHOWN follows insertion and no host spends nothing", () => {
	fetchLog.length = 0;
	global.document = bannerDoc();
	global.fetch = (url, opts) => {
		assert.ok(document.getElementById("passkey-portal-nudge"));
		return normalFetch(url, opts);
	};
	try {
		mod.renderNudgeBanner();
		assert.strictEqual(fetchLog.length, 1);
		assert.strictEqual(fetchLog[0].body.event, M.NUDGE_EVENTS.SHOWN);
		global.document = makeDoc();
		mod.renderNudgeBanner();
		assert.strictEqual(fetchLog.length, 1);
	} finally { global.fetch = normalFetch; }
});

test("portal: disabled modes suppress nudge and enforcement", async () => {
	global.document = bannerDoc();
	fetchLog.length = 0;
	frappeObj.boot = { passkeys: { enabled: false, nudge_state: { eligible: true },
		enforcement: { effective: "enforce", in_scope: true, degrade_nudge_eligible: true } } };
	mod.maybeEnforceOrNudge();
	await tick();
	assert.strictEqual(document.body.children.length, 0);
	assert.strictEqual(fetchLog.length, 0);
	delete frappeObj.boot;
});

test("portal: Degrade renders directly using enforcement cadence", async () => {
	for (const eligible of [true, false, undefined]) {
		global.document = bannerDoc();
		fetchLog.length = 0;
		frappeObj.boot = { passkeys: { enabled: true, credential_count: 0, nudge_state: { eligible: false },
			enforcement: { effective: "enforce", in_scope: true, incapable_policy: "degrade", degrade_nudge_eligible: eligible } } };
		mod.maybeEnforceOrNudge();
		await tick();
		assert.strictEqual(!!document.getElementById("passkey-portal-nudge"), eligible === true);
		assert.strictEqual(fetchLog.length, eligible === true ? 1 : 0);
	}
	delete frappeObj.boot;
});

function nudgeError() {
	return findNode(document.body, (n) => (n.className || "").includes("passkey-nudge-error"));
}

test("portal opt-out keeps the banner until saved; a failure shows a visible alert and stays retryable", async () => {
	try {
		for (const outcome of [true, false, "reject"]) {
			global.document = bannerDoc();
			let settle;
			global.fetch = () => new Promise((resolve, reject) => {
				settle = () => outcome === "reject" ? reject(new Error("offline")) :
					resolve({ ok: outcome, json: () => Promise.resolve({}) });
			});
			mod.renderNudgeBanner();
			settle(); // SHOWN
			const never = findButton(document.body, (b) => b.textContent === M.COPY.nudgeNever);
			never.click();
			never.click(); // a double click while saving sends nothing more
			assert.ok(document.getElementById("passkey-portal-nudge"), "banner stays while the opt-out is in flight");
			settle();
			await tick();
			if (outcome === true) {
				assert.strictEqual(document.getElementById("passkey-portal-nudge"), null, outcome);
				continue;
			}
			assert.ok(document.getElementById("passkey-portal-nudge"), "banner stays after a failed opt-out");
			assert.strictEqual(nudgeError().getAttribute("role"), "alert");
			assert.strictEqual(nudgeError().textContent, M.COPY.nudgeSaveFailed);
			global.fetch = () => Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
			never.click(); // retry succeeds
			await tick();
			assert.strictEqual(document.getElementById("passkey-portal-nudge"), null, "retry removes the banner");
		}
	} finally { global.fetch = normalFetch; }
});

const detectCapabilities = C.detectCapabilities;
function bootPortal(passkeys) {
	frappeObj.boot = { passkeys };
	C.detectCapabilities = () => Promise.resolve({ supported: true, uvpaa: true });
	delete require.cache[require.resolve("../../public/js/passkey_portal.bundle.js")];
	return require("../../public/js/passkey_portal.bundle.js");
}

test("portal /passkeys page shows no nudge banner (its own render would wipe a counted banner)", async () => {
	global.document = bannerDoc();
	const root = fakeEl("div");
	root.id = "passkey-portal-root";
	document.body.appendChild(root);
	fetchLog.length = 0;
	try {
		bootPortal({ enabled: true, credential_count: 0, nudge_state: { eligible: true } });
		await tick();
		assert.strictEqual(document.getElementById("passkey-portal-nudge"), null);
		assert.strictEqual(fetchLog.filter((f) => f.url.includes("record_nudge")).length, 0, "nothing counted");
	} finally { C.detectCapabilities = detectCapabilities; delete frappeObj.boot; }
});

test("portal boot merges the app catalog before its first paint", async () => {
	global.document = bannerDoc();
	window.__ = (str) => (frappeObj._messages && frappeObj._messages[str]) || str;
	global.fetch = (url, opts) => url.includes("get_app_translations")
		? Promise.resolve({ ok: true, json: () => Promise.resolve({ message: { [M.COPY.nudgeTitle]: "Connexion plus rapide" } }) })
		: normalFetch(url, opts);
	try {
		bootPortal({ enabled: true, credential_count: 0, nudge_state: { eligible: true } });
		await tick();
		const title = findNode(document.body, (n) => n.className === "passkey-nudge-title");
		assert.strictEqual(title.textContent, "Connexion plus rapide");
	} finally {
		global.fetch = normalFetch; C.detectCapabilities = detectCapabilities;
		delete frappeObj.boot; delete frappeObj._messages; delete window.__;
	}
});
