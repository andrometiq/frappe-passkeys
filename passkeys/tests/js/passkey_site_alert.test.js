const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { rpAlertDecision } = require("../../public/js/passkey_site_alert.bundle.js");

const problem = { reason: "host_outside_rp", status: "off", site_host: "new.example", rp_id: "old.example", suggested_rp_id: "new.example", working_origins: ["https://old.example"] };
for (const [status, fragment] of [["off", "requirements are paused"], ["app_only", "Only the mobile app"], ["web_works", "Passkeys work only at: {2}"]]) {
	test(`RP alert chooses ${status} copy`, () => {
		const decision = rpAlertDecision({ ...problem, status });
		assert.ok(decision.message.includes(fragment));
		assert.equal(decision.action, "Fix in Passkey Settings");
		assert.equal(decision.suggestion, "new.example");
		if (status === "web_works") assert.equal(decision.args[2], "https://old.example");
	});
}
test("RP alert distinguishes missing RP and invalid origins, suppresses healthy/absent diagnostics", () => {
	assert.equal(rpAlertDecision(null), null);
	assert.equal(rpAlertDecision({ reason: null, status: "web_works" }), null);
	assert.equal(rpAlertDecision({ ...problem, reason: "no_valid_origins" }).message, "Passkeys are off on this site: none of its origins is inside the RP ID {0}. Passkey requirements are paused until this is fixed.");
	assert.equal(rpAlertDecision({ ...problem, reason: "no_rp_id" }).action, "Open Passkey Settings");
});
function node() {
	return { children: [], attributes: {}, listeners: {}, setAttribute(k, v) { this.attributes[k] = v; },
		appendChild(child) { this.children.push(child); }, addEventListener(event, fn) { this.listeners[event] = fn; },
		insertBefore(child) { this.children.unshift(child); child.remove = () => { this.children = this.children.filter(c => c !== child); }; } };
}
function harness(alert, storage = new Map(), fallback = false) {
	const mount = node();
	const routes = [];
	const document = { readyState: "complete", createElement: node, querySelector(selector) {
		if (selector === ".passkey-site-alert") return mount.children[0] || null;
		return selector === (fallback ? "#body" : ".main-section") ? mount : null;
	} };
	const window = { sessionStorage: { getItem: k => storage.get(k), setItem: (k, v) => storage.set(k, v) },
		frappe: { boot: { passkeys: { rp_alert: alert } }, session: { user: "manager" }, set_route: (...args) => routes.push(args) } };
	vm.runInNewContext(fs.readFileSync(require.resolve("../../public/js/passkey_site_alert.bundle.js"), "utf8"), { window, document, __: (text, args = []) => text.replace(/\{(\d+)\}/g, (_, i) => args[i]) });
	return { mount, routes, storage };
}
for (const fallback of [true, false]) test(`RP alert DOM escapes values, suggests without saving, dismisses (${fallback})`, () => {
	const h = harness({ ...problem, site_host: "<img src=x>" }, new Map(), fallback);
	const bar = h.mount.children[0];
	assert.equal(bar.attributes.role, "status");
	assert.equal(bar.attributes["data-indicator"], "orange");
	assert.match(bar.children[0].textContent, /<img src=x>/);
	assert.equal(bar.children[0].innerHTML, undefined);
	bar.children[1].listeners.click();
	assert.equal(h.storage.get("passkeys:suggest_rp_id"), "new.example");
	assert.deepEqual(h.routes, [["Form", "Passkey Settings"]]);
	assert.equal(bar.children[2].attributes["aria-label"], "Dismiss");
	bar.children[2].listeners.click();
	assert.equal(h.mount.children.length, 0);
	assert.equal(harness({ ...problem, site_host: "<img src=x>" }, h.storage).mount.children.length, 0);
});
test("no admin diagnostic means no DOM alert", () => assert.equal(harness(undefined).mount.children.length, 0));
