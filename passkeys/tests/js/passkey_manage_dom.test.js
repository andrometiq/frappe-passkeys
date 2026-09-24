// The card DOM the desk and portal share (passkey_manage_common: cardList, emptyState,
// passkeyOnlyRow, createEnrollmentEvents). A hand-rolled DOM, no jsdom; its own process.
//
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");
const C = require("../../public/js/passkey_common.bundle.js");
const M = require("../../public/js/passkey_manage_common.bundle.js");

function fakeEl(tag) {
	const node = {
		tagName: String(tag).toUpperCase(), className: "", textContent: "", innerHTML: "",
		_attrs: {}, _listeners: {}, children: [],
		setAttribute(k, v) { node._attrs[k] = v; },
		getAttribute(k) { return node._attrs[k]; },
		appendChild(c) { node.children.push(c); return c; },
		addEventListener(type, fn) { (node._listeners[type] = node._listeners[type] || []).push(fn); },
		dispatch(type) { (node._listeners[type] || []).forEach((fn) => fn({})); },
	};
	return node;
}
function find(root, pred) {
	if (pred(root)) return root;
	for (const c of root.children) { const f = find(c, pred); if (f) return f; }
	return null;
}
const byClass = (root, cls) => find(root, (n) => n.className.split(" ").includes(cls));

global.document = { createElement: fakeEl, getElementById: () => null };
global.window = { frappe: { passkeys_common: C } };

test("cardList: one labelled list item per credential; actions only when asked for", () => {
	const creds = [
		{ name: "WC-1", label: "Phone", backup_state: 1, enabled: 1, creation: "2026-01-01" },
		{ name: "WC-2", label: "Key", enabled: 0, flagged: 1 },
	];
	const renamed = [];
	const list = M.cardList(creds, {}, (vm) => ({ onRename: () => renamed.push(vm.name), onDelete() {} }));
	assert.strictEqual(list.tagName, "UL");
	assert.strictEqual(list.getAttribute("role"), "list");
	assert.deepStrictEqual(list.children.map((li) => li.getAttribute("data-name")), ["WC-1", "WC-2"]);
	const synced = byClass(list.children[0], "indicator-pill");
	assert.strictEqual(synced.textContent, M.COPY.syncedBadge);
	assert.ok(synced.className.includes("green"));
	assert.ok(list.children[1].className.includes("passkey-card-disabled"));
	const flagged = find(list.children[1], (n) => (n.className || "").includes("alert-danger"));
	assert.strictEqual(flagged.getAttribute("role"), "alert");
	assert.ok(byClass(list.children[1], "gray"), "a disabled credential carries the gray pill");

	const rename = byClass(list.children[0], "passkey-rename");
	assert.strictEqual(rename.getAttribute("aria-label"), "Rename passkey Phone", "icon-only action has an accessible name");
	rename.dispatch("click");
	assert.deepStrictEqual(renamed, ["WC-1"]);

	const readOnly = M.cardList(creds, {}, () => null);
	assert.strictEqual(byClass(readOnly, "passkey-card-actions"), null, "a read-only list has no actions");
});

test("emptyState: the add call to action", () => {
	let added = 0;
	const empty = M.emptyState(() => { added += 1; });
	assert.ok(empty.className.includes("text-muted") && empty.className.includes("text-center"));
	const cta = byClass(empty, "btn-primary");
	assert.strictEqual(cta.textContent, M.COPY.addButton);
	cta.dispatch("click");
	assert.strictEqual(added, 1);
});

test("passkeyOnlyRow: snaps back and asks; needs two enabled passkeys to turn on", () => {
	const requests = [];
	const two = { credentials: [{ enabled: 1 }, { enabled: 1 }], passkey_only_login: 0 };
	const toggle = byClass(M.passkeyOnlyRow(two, (d) => requests.push(d)), "passkey-only-toggle");
	assert.strictEqual(toggle.getAttribute("role"), "switch");
	assert.strictEqual(toggle.disabled, undefined);
	toggle.checked = true;
	toggle.dispatch("change");
	assert.strictEqual(toggle.checked, false, "never flips before the server confirms");
	assert.deepStrictEqual(requests, [true]);

	const one = { credentials: [{ enabled: 1 }, { enabled: 0 }], passkey_only_login: 0 };
	assert.strictEqual(byClass(M.passkeyOnlyRow(one, () => {}), "passkey-only-toggle").disabled, true);
	const on = { credentials: [{ enabled: 1 }], passkey_only_login: 1 };
	assert.strictEqual(byClass(M.passkeyOnlyRow(on, () => {}), "passkey-only-toggle").disabled, undefined, "turning it off is always allowed");
});

test("createEnrollmentEvents: one defer per verdict, one incapable report per page", async () => {
	const posts = [];
	const events = M.createEnrollmentEvents((method, body) => {
		posts.push([method, body.event]);
		return Promise.resolve({ ok: true });
	});
	const boot = { enforcement: { policy: "Enforce" } };
	await events.recordEnforcementDefer(boot, { graceRemaining: 2 });
	await events.recordEnforcementDefer(boot, { graceRemaining: 2 });
	events.reportIncapableOnce();
	events.reportIncapableOnce();
	assert.deepStrictEqual(posts, [
		[M.MANAGE_METHODS.recordEnforcement, M.ENFORCE_EVENTS.DEFER],
		[M.MANAGE_METHODS.recordEnforcement, M.ENFORCE_EVENTS.INCAPABLE],
	]);

	const offline = M.createEnrollmentEvents(() => Promise.reject(new Error("offline")));
	assert.strictEqual(await offline.recordNudge(M.NUDGE_EVENTS.SHOWN), null, "recordNudge never rejects");
});
