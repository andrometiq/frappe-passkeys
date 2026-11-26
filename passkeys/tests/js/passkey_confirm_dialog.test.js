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

// A frappe.ui.Dialog-compatible stub: fields, footer actions, and a queryable alert node.
function makeDialogClass() {
	function nodeFromHtml(html) {
		const el = {
			textContent: "", _attrs: {},
			setAttribute(k, v) { this._attrs[k] = v; },
			getAttribute(k) { return this._attrs[k]; },
			removeAttribute(k) { delete this._attrs[k]; },
		};
		const role = /role="([^"]*)"/.exec(html || "");
		const live = /aria-live="([^"]*)"/.exec(html || "");
		if (role) el._attrs.role = role[1];
		if (live) el._attrs["aria-live"] = live[1];
		return el;
	}
	function FakeDialog(opts) {
		opts = opts || {};
		this.opts = opts;
		this.fields_dict = {};
		(opts.fields || []).forEach((df) => {
			const store = { html: df.options || "" };
			const msg = nodeFromHtml(store.html);
			this.fields_dict[df.fieldname] = {
				df,
				$wrapper: {
					html(h) { if (h === undefined) return store.html; store.html = h; return this; },
					get() { return { querySelector: (sel) => (store.html.indexOf(String(sel).replace(/^\./, "")) === -1 ? null : msg) }; },
				},
				$input: {
					className: "", value: "", handlers: {},
					addClass(c) { this.className += " " + c; },
					on(type, fn) { this.handlers[type] = fn; },
					focus() {},
				},
			};
		});
		this._primary = { className: "", handlers: {}, _props: {}, focus() {}, addClass(c) { this.className += " " + c; }, removeClass(c) { this.className = this.className.replace(c, ""); }, prop(k, v) { this._props[k] = v; this.disabled = v; } };
		this._secondary = { className: "", addClass(c) { this.className += " " + c; } };
		const handlers = {};
		this.$wrapper = {
			on(type, fn) { (handlers[type] = handlers[type] || []).push(fn); return this; },
			one() { return this; },
			modal() {},
			trigger(type) { (handlers[type] || []).slice().forEach((fn) => fn()); },
		};
		this.show = function () { this.display = true; };
		// As Bootstrap does: Esc, the close button, a route change and done() all hide through here.
		this.hide = function () { this.display = false; this.$wrapper.trigger("hide.bs.modal"); };
		FakeDialog.instances.push(this);
	}
	FakeDialog.prototype.set_df_property = function (name, prop, value) {
		this.fields_dict[name].df[prop] = value;
	};
	FakeDialog.prototype.get_value = function (name) { return this.fields_dict[name].$input.value; };
	FakeDialog.prototype.set_value = function (name, value) { this.fields_dict[name].$input.value = value; };
	FakeDialog.prototype.set_primary_action = function (label, fn) {
		this._primaryLabel = label;
		this._primary.handlers.click = fn;
	};
	FakeDialog.prototype.set_secondary_action_label = function (label) { this._secondaryLabel = label; };
	FakeDialog.prototype.set_secondary_action = function (fn) { this._secondary.handlers = { click: fn }; };
	FakeDialog.prototype.get_primary_btn = function () { return this._primary; };
	FakeDialog.prototype.get_secondary_btn = function () { return this._secondary; };
	FakeDialog.instances = [];
	return FakeDialog;
}

test("C3: collectPassword self-creates the dialog on the straight-to-password route (no crash, prompt renders)", async () => {
	const doc = makeDoc();
	const Dialog = makeDialogClass();
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
	const password = Dialog.instances[0].fields_dict.password;
	assert.strictEqual(password.df.fieldtype, "Password");
	assert.strictEqual(password.df.label, "Password");
	assert.strictEqual(password.df.hidden, 0);
	assert.ok(password.$input.className.includes("passkey-confirm-pw"));
});

test("a wrong-password message stays in the re-rendered prompt until the next submit", async () => {
	const doc = makeDoc();
	const Dialog = makeDialogClass();
	global.document = doc;
	Object.defineProperty(globalThis, "navigator", { configurable: true, value: {}, writable: true }); // Node 21+: getter-only global
	global.window = { frappe: { passkeys_common: C, ui: { Dialog: Dialog } } };
	delete require.cache[require.resolve("../../public/js/passkey_confirm.bundle.js")];
	const ui = require("../../public/js/passkey_confirm.bundle.js").makeDialogUI();
	const msgBox = () => Dialog.instances[0].fields_dict.alert.$wrapper.get(0).querySelector(".passkey-confirm-msg");

	ui.collectPassword();
	const message = "That password wasn't right. Try again.";
	// The engine's order on a refused password: passwordError(), then collectPassword() again.
	ui.passwordError(message);
	const retry = ui.collectPassword();
	const box = msgBox();
	assert.ok(box, "the re-rendered prompt has a message box");
	assert.strictEqual(box.textContent, message, "the error survives the re-render");
	assert.strictEqual(box.getAttribute("role"), "alert", "the error box is announced as an alert");

	Dialog.instances[0].get_primary_btn().handlers.click();
	assert.strictEqual(await retry, "", "submit resolves the retry");
	ui.collectPassword();
	assert.strictEqual(msgBox().textContent, "", "a retry clears the old error");
	Dialog.instances[0].set_value("password", "secret");
	let entered = null;
	const viaEnter = ui.collectPassword();
	// collectPassword above replaced the prompt; the previous one already settled.
	Dialog.instances[0].fields_dict.password.$input.handlers.keydown({ key: "Enter", preventDefault() {} });
	entered = await viaEnter;
	assert.strictEqual(entered, "secret", "Enter submits the password field");
});

test("the desk dialog opens without the fade, so it is on screen when the engine opens the prompt", () => {
	const Dialog = makeDialogClass();
	global.document = makeDoc();
	Object.defineProperty(globalThis, "navigator", { configurable: true, value: {}, writable: true });
	global.window = { frappe: { passkeys_common: C, ui: { Dialog: Dialog } } };
	delete require.cache[require.resolve("../../public/js/passkey_confirm.bundle.js")];
	const ui = require("../../public/js/passkey_confirm.bundle.js").makeDialogUI();

	ui.chooseMethod({ action: "myapp.release_payment", canPasskey: true, canPassword: true });
	assert.strictEqual(Dialog.instances.length, 1);
	// Bootstrap's fade keeps the modal display:none for ~150 ms after show(); the engine waits one frame.
	assert.strictEqual(Dialog.instances[0].opts.animate, false);
});

test("focus goes back to the opener when the dialog was closed before done()", () => {
	const Dialog = makeDialogClass();
	const doc = makeDoc();
	let focused = false;
	doc.activeElement = { focus() { focused = true; } };
	global.document = doc;
	Object.defineProperty(globalThis, "navigator", { configurable: true, value: {}, writable: true });
	global.window = { frappe: { passkeys_common: C, ui: { Dialog: Dialog } } };
	delete require.cache[require.resolve("../../public/js/passkey_confirm.bundle.js")];
	const ui = require("../../public/js/passkey_confirm.bundle.js").makeDialogUI();

	ui.chooseMethod({ action: "myapp.release_payment", canPasskey: true, canPassword: true }).catch(() => {});
	// Esc hid the dialog at once (no fade), so no hidden.bs.modal follows done().
	Dialog.instances[0].display = false;
	ui.done(false);
	assert.strictEqual(focused, true);
});

test("closing the desk dialog after the pick reports the cancel to the engine; done()'s own close does not", async () => {
	const Dialog = makeDialogClass();
	global.document = makeDoc();
	Object.defineProperty(globalThis, "navigator", { configurable: true, value: {}, writable: true });
	global.window = { frappe: { passkeys_common: C, ui: { Dialog: Dialog } } };
	delete require.cache[require.resolve("../../public/js/passkey_confirm.bundle.js")];
	const { makeDialogUI } = require("../../public/js/passkey_confirm.bundle.js");
	let cancels = 0;
	const choice = { action: "myapp.release_payment", canPasskey: true, canPassword: true, cancel: () => { cancels += 1; } };

	const ui = makeDialogUI();
	const picked = ui.chooseMethod(choice);
	Dialog.instances[0].get_primary_btn().handlers.click();
	assert.strictEqual(await picked, "passkey");
	ui.busy(true);
	Dialog.instances[0].hide(); // Esc while the passkey prompt is open
	assert.strictEqual(cancels, 1, "the close after the pick reached the engine");

	const finished = makeDialogUI();
	finished.chooseMethod(choice);
	finished.done(true);
	assert.strictEqual(Dialog.instances[1].display, false, "done() closed the dialog");
	assert.strictEqual(cancels, 1, "the engine's own close is not a cancel");
	// Without `cancel` in the choice, a close only rejects chooseMethod, as before.
	const plain = makeDialogUI().chooseMethod({ action: "myapp.release_payment", canPasskey: true, canPassword: false });
	Dialog.instances[2].hide();
	await assert.rejects(plain, (e) => e.code === C.CONFIRM_CODES.USER_CANCELLED);
});

test("closing the desk dialog while a password-only check runs reports one cancel to the engine; done()'s own close does not", async () => {
	const Dialog = makeDialogClass();
	global.document = makeDoc();
	Object.defineProperty(globalThis, "navigator", { configurable: true, value: {}, writable: true });
	global.window = { frappe: { passkeys_common: C, ui: { Dialog: Dialog } } };
	delete require.cache[require.resolve("../../public/js/passkey_confirm.bundle.js")];
	const { makeDialogUI } = require("../../public/js/passkey_confirm.bundle.js");
	let cancels = 0;
	const context = { action: "myapp.release_payment", cancel: () => { cancels += 1; } };

	// No chooseMethod: the engine opens straight on the password prompt, and again after a wrong one.
	const ui = makeDialogUI();
	const first = ui.collectPassword(context);
	Dialog.instances[0].get_primary_btn().handlers.click();
	await first;
	ui.passwordError("That password wasn't right. Try again.");
	const retry = ui.collectPassword(context);
	Dialog.instances[0].get_primary_btn().handlers.click();
	await retry;
	Dialog.instances[0].hide(); // Esc while the second password is checked
	assert.strictEqual(cancels, 1, "the close reached the engine once");

	const finished = makeDialogUI();
	finished.collectPassword(context);
	finished.done(true);
	assert.strictEqual(Dialog.instances[1].display, false, "done() closed the dialog");
	assert.strictEqual(cancels, 1, "the engine's own close is not a cancel");
});

test("frappe.passkeys.call on Desk shows a success's server messages with frappe.msgprint, as frappe.call does", async () => {
	const warning = { message: "Some of a@example.com's sessions may still be signed in: see <a href=\"https://example.com/r\">recovery</a>.", indicator: "orange" };
	const shown = [];
	global.document = makeDoc();
	Object.defineProperty(globalThis, "navigator", { configurable: true, value: {}, writable: true });
	global.window = {
		frappe: {
			passkeys_common: C, ui: { Dialog: makeDialogClass() },
			hide_msgprint() { shown.push("hide"); },
			msgprint(messages) { shown.push(messages); },
		},
	};
	global.fetch = () => Promise.resolve({
		ok: true, status: 200,
		json: () => Promise.resolve({ message: { deleted: "x" }, _server_messages: JSON.stringify([JSON.stringify(warning)]) }),
	});
	delete require.cache[require.resolve("../../public/js/passkey_confirm.bundle.js")];
	require("../../public/js/passkey_confirm.bundle.js");

	const result = await window.frappe.passkeys.call("passkeys.api.credentials.delete_credential", { name: "x" });
	assert.deepStrictEqual(result, { deleted: "x" });
	assert.deepStrictEqual(shown, ["hide", [warning]]);
});
