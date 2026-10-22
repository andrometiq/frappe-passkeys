const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const C = require("../../public/js/passkey_common.bundle.js");
const M = require("../../public/js/passkey_manage_common.bundle.js");
const impact = { stop: { passkeys: 3, users: 2 }, start: { passkeys: 4, users: 1 }, new_rp_id: "new.example", new_off: false };
function harness() {
	const calls = [], warns = [], notices = [];
	let handlers, dialog;
	const context = { window: {}, __: (text, args = []) => text.replace(/\{(\d+)\}/g, (_, i) => args[i]),
		frappe: { passkeys_common: C, passkeys_manage_common: M, call: o => calls.push(o),
			show_alert: o => notices.push(o),
			ui: { form: { on: (_, value) => { handlers = value; } }, Dialog: function (options) {
				dialog = { options, show() {}, hide() {}, get_primary_btn() {} }; return dialog;
			} },
			warn: (...args) => { const d = { $wrapper: { on: (_, fn) => { d.hide = fn; } } }; warns.push({ args, d }); return d; } } };
	vm.createContext(context);
	vm.runInContext(fs.readFileSync(require.resolve("../../public/js/passkey_settings.js"), "utf8"), context);
	context.paintBanners = () => {};
	const frm = { doc: { passkey_rp_id: "new.example", passkey_origins: "https://new.example" }, _passkey_rpid_saved: "old.example",
		set_value: (field, value) => { frm.doc[field] = value; }, scroll_to_field: value => { frm.scrolled = value; } };
	return { context, frm, calls, warns, notices, handlers, get dialog() { return dialog; } };
}
test("RP confirmation waits for server counts, escapes values, and acknowledges only the previewed inputs", () => {
	const h = harness();
	h.context.confirmRpIdChange(h.frm);
	assert.equal(h.warns.length, 0);
	assert.equal(h.calls[0].args.rp_id, "new.example");
	assert.equal(h.calls[0].args.passkey_origins, "https://new.example");
	h.calls[0].callback({ message: { ...impact, new_rp_id: "<img>" } });
	assert.match(h.warns[0].args[1], /3 passkey\(s\) of 2 user\(s\) will stop/);
	assert.match(h.warns[0].args[1], /4 passkey\(s\) of 1 user\(s\) made for &lt;img&gt; will work again/);
	h.warns[0].args[2](); h.warns[0].d.hide();
	assert.equal(h.context.rpIdChangeUnconfirmed(h.frm), false);
	h.frm.doc.passkey_origins = "https://other.new.example";
	assert.equal(h.context.rpIdChangeUnconfirmed(h.frm), true);
});
test("late impact responses cannot confirm a newer candidate; cancellation restores the saved RP", () => {
	const h = harness();
	h.context.confirmRpIdChange(h.frm);
	h.frm.doc.passkey_rp_id = "other.example";
	h.calls[0].callback({ message: impact });
	assert.equal(h.warns.length, 0);
	h.context.confirmRpIdChange(h.frm);
	h.calls[1].callback({ message: impact });
	h.warns[0].d.hide();
	assert.equal(h.frm.doc.passkey_rp_id, "old.example");
});
test("invalid candidates produce a field error and no confirmation or acknowledgement", () => {
	const h = harness();
	h.context.confirmRpIdChange(h.frm);
	h.calls[0].error({ responseJSON: { exc_type: "ValidationError", _server_messages: JSON.stringify([JSON.stringify({ message: "Invalid origin" })]) } });
	assert.equal(h.frm._passkey_rpid_error, "Invalid origin");
	assert.equal(h.warns.length, 0);
	assert.equal(h.context.rpIdChangeUnconfirmed(h.frm), true);
});
test("valid off candidates show the off warning and zero-stop copy", () => {
	const h = harness();
	const text = h.context.rpImpactMessage({ ...impact, stop: { passkeys: 0, users: 0 }, new_off: true });
	assert.match(text, /No passkeys stop working/);
	assert.match(text, /Passkeys would be off on this site with this RP ID/);
});
test("suggestion is consumed once and fills and scrolls without saving", async () => {
	const h = harness();
	const storage = new Map([["passkeys:suggest_rp_id", "suggested.example"]]);
	h.context.window.sessionStorage = { getItem: k => storage.get(k), removeItem: k => storage.delete(k) };
	h.context.pickupRpSuggestion(h.frm);
	await Promise.resolve();
	assert.equal(h.frm.doc.passkey_rp_id, "suggested.example");
	assert.equal(h.frm.scrolled, "passkey_rp_id");
	assert.equal(storage.size, 0);
	h.frm.doc.passkey_rp_id = "typed.example";
	h.context.pickupRpSuggestion(h.frm);
	assert.equal(h.frm.doc.passkey_rp_id, "typed.example");
	assert.equal(h.calls.length, 0);
});
test("bulk action confirms removable count and sends saved site RP, then refreshes", () => {
	const h = harness();
	h.context.removeStalePasskeys(h.frm, { site_rp_id: "saved.example", passkeys: 8, removable: 6 });
	assert.match(h.dialog.options.fields[0].options, /Remove 6 passkey/);
	assert.match(h.dialog.options.fields[0].options, /Flagged passkeys are kept for review/);
	assert.equal(h.calls.length, 0);
	h.dialog.options.primary_action();
	assert.equal(h.calls[0].args.site_rp_id, "saved.example");
	h.calls[0].callback({ message: { removed: 6 } });
	assert.equal(h.notices[0].message, "Removed 6 passkey(s).");
	assert.ok(h.calls[1].method.endsWith(".get_settings_context"));
});
function element(tag) {
	return { tag, className: "", textContent: "", children: [], style: {}, attrs: {},
		setAttribute(k, v) { this.attrs[k] = v; }, appendChild(child) { this.children.push(child); },
		get innerHTML() { return this.children.map(child => `<${child.tag || "text"} class="${child.className || ""}">${child.textContent || ""}${child.innerHTML || ""}</${child.tag || "text"}>`).join(""); } };
}
test("resolved field shows stale counts and removable action only when eligible, plus accessible validation", () => {
	const h = harness();
	let html, clicked;
	const attrs = {};
	h.context.document = { createElement: element, createTextNode: text => ({ textContent: text }) };
	h.frm.fields_dict = { passkey_rp_id: { $input: { attr: (k, v) => { attrs[k] = v; } } } };
	h.frm.get_field = () => ({ html: value => { html = value; }, $wrapper: { find: () => ({ on: (_, callback) => { clicked = callback; } }) } });
	const stale = { site_rp_id: "new.example", passkeys: 3, users: 2, removable: 1 };
	h.frm._passkey_settings_context = { stale_passkeys: stale };
	h.frm._passkey_rpid_error = "Invalid origin";
	h.frm._passkey_rpid_error_candidate = h.context.rpCandidate(h.frm);
	h.context.paintResolvedConfig(h.frm, { resolvedRpId: "new.example", resolvedOrigins: [] });
	assert.match(html, /3 passkey\(s\) of 2 user\(s\) were made for another RP ID/);
	assert.match(html, /Remove stale passkeys/);
	assert.match(html, /Invalid origin/);
	assert.equal(attrs["aria-invalid"], "true");
	clicked();
	assert.match(h.dialog.options.fields[0].options, /Remove 1 passkey/);
	h.context.frappe.boot = { passkeys: { impersonated: true } };
	h.context.paintResolvedConfig(h.frm, { resolvedRpId: "new.example", resolvedOrigins: [] });
	assert.doesNotMatch(html, /Remove stale passkeys/);
	h.context.frappe.boot.passkeys.impersonated = false;
	stale.removable = 0;
	h.frm.doc.passkey_rp_id = "edited.example";
	h.context.paintResolvedConfig(h.frm, { resolvedRpId: "edited.example", resolvedOrigins: [] });
	assert.doesNotMatch(html, /Remove stale passkeys|Invalid origin/);
	assert.equal(attrs["aria-invalid"], "false");
	h.frm._passkey_settings_context.stale_passkeys = null;
	h.context.paintResolvedConfig(h.frm, { resolvedRpId: "edited.example", resolvedOrigins: [] });
	assert.doesNotMatch(html, /were made for another RP ID/);
});
