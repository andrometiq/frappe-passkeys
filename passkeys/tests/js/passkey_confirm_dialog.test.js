// passkey_confirm_dialog.test.js — the ONE DOM-adapter test for passkey_confirm.bundle.js
// (C3). Everything else in the confirm client is pure and lives in passkey_common.bundle.js;
// this covers the frappe.ui.Dialog UI factory's straight-to-password crash and the
// wrong-password message surviving the prompt's re-render.
//
// The engine can route STRAIGHT to the password leg (caps.passkey false — a
// zero-credential Desk user, or an expired sudo window) WITHOUT ever calling
// chooseMethod, so collectPassword() runs before any dialog exists. It must create
// the dialog itself; the old code dereferenced a null dialog in setContent() and
// crashed (TypeError). No bench / no jsdom — a tiny hand-rolled DOM + a
// frappe.ui.Dialog-compatible stub is enough for what makeDialogUI touches. The
// node runner executes each test file in its own process, so the window/document
// globals set here don't leak into the pure suites.
//
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");

const C = require("../../public/js/passkey_common.bundle.js");

// --------------------------------------------------- minimal DOM stub (no jsdom)
function makeDoc() {
	const byId = {};
	const doc = {
		activeElement: null,
		getElementById(id) { return byId[id] || null; },
		createElement(tag) {
			return {
				tagName: tag, id: "", className: "", _attrs: {},
				setAttribute(k, v) { this._attrs[k] = v; },
				appendChild() {},
			};
		},
		addEventListener() {},
		removeEventListener() {},
	};
	doc.body = { appendChild(n) { if (n && n.id) byId[n.id] = n; } };
	doc.documentElement = doc.body;
	return doc;
}

// A frappe.ui.Dialog-compatible stub: $body.html(markup) stores it, $body.get(0)
// returns a body element whose querySelector resolves classes present in the markup.
function makeDialogClass(doc) {
	function FakeDialog() {
		// One element per class per render, so listeners attached after a render can be fired.
		const store = { html: "", nodes: {} };
		const bodyEl = {
			ownerDocument: doc,
			querySelector(sel) {
				const cls = String(sel).replace(/^\./, "");
				if (store.html.indexOf(cls) === -1) return null;
				if (!store.nodes[cls]) {
					store.nodes[cls] = {
						value: "", textContent: "", handlers: {}, focus() {},
						addEventListener(type, fn) { this.handlers[type] = fn; },
					};
				}
				return store.nodes[cls];
			},
		};
		this._store = store;
		this.$body = {
			html(h) { if (h === undefined) return store.html; store.html = h; store.nodes = {}; return this; },
			get() { return bodyEl; },
		};
		this.show = function () {};
		this.hide = function () {};
		FakeDialog.instances.push(this);
	}
	FakeDialog.instances = [];
	return FakeDialog;
}

test("C3: collectPassword self-creates the dialog on the straight-to-password route (no crash, prompt renders)", async () => {
	const doc = makeDoc();
	const Dialog = makeDialogClass(doc);
	global.document = doc;
	Object.defineProperty(globalThis, "navigator", { configurable: true, value: {}, writable: true }); // Node 21+: getter-only global
	global.window = { frappe: { passkeys_common: C, ui: { Dialog: Dialog } } };

	// require AFTER the globals exist — the confirm bundle reads window at load
	delete require.cache[require.resolve("../../public/js/passkey_confirm.bundle.js")];
	const confirmMod = require("../../public/js/passkey_confirm.bundle.js");
	assert.strictEqual(typeof confirmMod.makeDialogUI, "function", "node test seam must be exported");

	const ui = confirmMod.makeDialogUI();

	// dialog is null here — chooseMethod was never called (caps.passkey false).
	let rejected = null;
	const p = ui.collectPassword();
	p.then(() => {}, (e) => { rejected = e; });
	await Promise.resolve();
	await Promise.resolve();

	assert.strictEqual(rejected, null, "must NOT reject with a TypeError when the dialog was never opened");
	assert.strictEqual(Dialog.instances.length, 1, "collectPassword must create the dialog itself");
	assert.ok(
		Dialog.instances[0]._store.html.indexOf("passkey-confirm-pw") !== -1,
		"the password prompt must render into the freshly-created dialog"
	);
});

test("a wrong-password message stays in the re-rendered prompt until the next submit", async () => {
	const doc = makeDoc();
	const Dialog = makeDialogClass(doc);
	global.document = doc;
	Object.defineProperty(globalThis, "navigator", { configurable: true, value: {}, writable: true }); // Node 21+: getter-only global
	global.window = { frappe: { passkeys_common: C, ui: { Dialog: Dialog } } };
	delete require.cache[require.resolve("../../public/js/passkey_confirm.bundle.js")];
	const ui = require("../../public/js/passkey_confirm.bundle.js").makeDialogUI();
	const msgBox = () => Dialog.instances[0]._store.html.match(/<div class="passkey-confirm-msg"[^>]*>([^<]*)<\/div>/);

	ui.collectPassword();
	const message = "That password wasn't right. Try again.";
	// The engine's order on a refused password: passwordError(), then collectPassword() again.
	ui.passwordError(message);
	const retry = ui.collectPassword();
	const box = msgBox();
	assert.ok(box, "the re-rendered prompt has a message box");
	assert.strictEqual(box[1], "That password wasn&#39;t right. Try again.", "the error survives the re-render (escaped)");
	assert.match(box[0], /role="alert"/, "the error box is announced as an alert");

	Dialog.instances[0].$body.get().querySelector(".passkey-confirm-pwgo").handlers.click();
	assert.strictEqual(await retry, "", "submit resolves the retry");
	ui.collectPassword();
	assert.strictEqual(msgBox()[1], "", "a retry clears the old error");
});
