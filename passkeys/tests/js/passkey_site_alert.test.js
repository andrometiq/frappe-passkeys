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
	return { children: [], attributes: {}, listeners: {}, parentNode: null, hidden: false,
		get firstChild() { return this.children[0] || null; },
		get nextSibling() { const c = this.parentNode ? this.parentNode.children : []; return c[c.indexOf(this) + 1] || null; },
		get isConnected() { let n = this; while (n.parentNode) n = n.parentNode; return !!n.isRoot; },
		get previousSibling() { const c = this.parentNode ? this.parentNode.children : []; return c[c.indexOf(this) - 1] || null; },
		getClientRects() { return this.hidden ? [] : [{}]; },
		setAttribute(k, v) { this.attributes[k] = v; },
		appendChild(child) { child.remove(); this.children.push(child); child.parentNode = this; },
		addEventListener(event, fn) { this.listeners[event] = fn; },
		remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(c => c !== this); this.parentNode = null; },
		insertBefore(child, before) { child.remove(); const index = this.children.indexOf(before); this.children.splice(index < 0 ? this.children.length : index, 0, child); child.parentNode = this; } };
}
function harness(alert, storage = new Map(), fallback = false) {
	const shell = node(), header = node(), body = node(), mount = fallback ? body : node();
	shell.isRoot = true;
	const observers = [];
	shell.appendChild(header);
	shell.appendChild(body);
	if (!fallback) body.appendChild(mount);
	const pages = fallback ? [] : [mount];
	const routes = [], handlers = {};
	function findBar(parent) {
		if ((parent.className || "").includes("passkey-site-alert")) return parent;
		return parent.children.map(findBar).find(Boolean) || null;
	}
	const document = { readyState: "complete", createElement: node, querySelectorAll: selector => selector === ".page-container" ? pages : [],
		querySelector(selector) {
			if (selector === ".passkey-site-alert") return findBar(shell);
			return selector === ".main-section" ? shell : selector === "#body" ? body : null;
		} };
	const window = { sessionStorage: { getItem: k => storage.get(k), setItem: (k, v) => storage.set(k, v) },
		$: () => ({ on: (event, fn) => { handlers[event] = fn; } }),
		MutationObserver: function (fn) { this.fn = fn; this.observe = (target) => { this.target = target; observers.push(this); };
			this.disconnect = () => { observers.splice(observers.indexOf(this), 1); }; },
		frappe: { container: { page: fallback ? null : mount }, after_ajax: fn => fn(),
			boot: { passkeys: { rp_alert: alert } }, session: { user: "manager" }, set_route: (...args) => routes.push(args) } };
	vm.runInNewContext(fs.readFileSync(require.resolve("../../public/js/passkey_site_alert.bundle.js"), "utf8"), { window, document, __: (text, args = []) => text.replace(/\{(\d+)\}/g, (_, i) => args[i]) });
	return { mount, shell, header, body, pages, window, routes, storage, observers,
		pageChange: () => handlers["page-change"](), mutate: () => observers.slice().forEach(o => o.fn()) };
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

test("RP alert moves the same bar across workspace, list and form pages below the header", () => {
	const h = harness(problem);
	const bar = h.mount.firstChild;
	assert.ok(bar);
	assert.equal(h.shell.firstChild, h.header);
	for (let i = 0; i < 3; i++) {
		const previous = h.window.frappe.container.page;
		previous.hidden = true;
		const page = node(), content = node();
		page.appendChild(content);
		h.pages.push(page);
		h.body.appendChild(page);
		h.window.frappe.container.page = page;
		h.pageChange();
		h.pageChange();
		assert.equal(page.firstChild, bar);
		assert.deepEqual(page.children, [bar, content]);
		assert.equal(previous.children.includes(bar), false);
	}
	bar.children[2].listeners.click();
	h.pageChange();
	assert.equal(h.window.frappe.container.page.children.length, 1);
});
test("RP alert moves from the body fallback to a visible page without container.page", () => {
	const h = harness(problem, new Map(), true);
	const bar = h.body.firstChild;
	const hidden = node(), visible = node();
	hidden.hidden = true;
	h.pages.push(hidden, visible);
	h.body.appendChild(hidden);
	h.body.appendChild(visible);
	h.pageChange();
	assert.equal(visible.firstChild, bar);
	assert.equal(hidden.children.length, 0);
	assert.equal(h.shell.firstChild, h.header);
});
test("RP alert sits below a navbar the page renders itself", () => {
	const h = harness(problem);
	const bar = h.mount.firstChild;
	const page = node(), wrapper = node(), navbar = node(), content = node();
	wrapper.appendChild(navbar);
	wrapper.appendChild(content);
	page.appendChild(wrapper);
	page.querySelectorAll = selector => (selector === "header[class*='navbar']" ? [navbar] : []);
	h.pages.push(page);
	h.body.appendChild(page);
	h.window.frappe.container.page = page;
	h.pageChange();
	h.pageChange();
	assert.deepEqual(wrapper.children, [navbar, bar, content]);
	navbar.hidden = true;
	h.pageChange();
	assert.equal(page.firstChild, bar);
});
test("RP alert comes back when the page rebuilds its content and drops it", () => {
	const h = harness(problem);
	assert.equal(h.observers.length, 1);
	assert.equal(h.observers[0].target, h.mount);
	const dropped = h.mount.firstChild;
	dropped.remove();
	assert.equal(dropped.isConnected, false);
	h.mutate();
	assert.ok((h.mount.firstChild.className || "").includes("passkey-site-alert"));
	assert.notEqual(h.mount.firstChild, dropped);
	assert.equal(h.observers.length, 1);
	h.mount.firstChild.children[2].listeners.click();
	assert.equal(h.observers.length, 0);
});
