// passkey_login_second_factor.test.js — the second-factor dialog.
//
// The passkey sheet opens with the dialog, without a click; if the browser refuses it or the
// user cancels it, the dialog stays as it was, with no error. Closing the dialog or choosing
// the code cancels the request, and an autofill request is paused while the dialog is open. Once
// an assertion is posted, the dialog can't be closed until the verify settles. setDialogError
// paints the dialog's alert AND announces it, so a failure must reach the live region exactly
// once (a second announce() made screen readers hear it twice), and a failed verify must release
// the ceremony so the user can retry.
//
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");

const C = require("../../public/js/passkey_common.bundle.js");

const realSetTimeout = global.setTimeout;
const tick = () => new Promise((resolve) => realSetTimeout(resolve, 0));
// Swallow the bundle's boot timer and the dialog's deferred focus.
global.setTimeout = function () { return 0; };
global.clearTimeout = function () {};

// Minimal DOM: querySelector returns one stable child per selector, and buttons keep
// their click listeners.
function fakeEl(tag) {
	const children = {};
	const node = {
		tagName: String(tag || "").toUpperCase(),
		className: "", textContent: "", innerHTML: "", type: "", parentNode: null,
		_attrs: {}, _listeners: {}, appended: [],
		setAttribute(k, v) { node._attrs[k] = v; },
		appendChild(child) { child.parentNode = node; node.appended.push(child); return child; },
		removeChild(child) { child.parentNode = null; return child; },
		addEventListener(type, fn) { (node._listeners[type] = node._listeners[type] || []).push(fn); },
		click() { (node._listeners.click || []).forEach((fn) => fn({})); },
		contains() { return false; },
		focus() {},
		querySelector(sel) { return (children[sel] = children[sel] || fakeEl("div")); },
		querySelectorAll() { return []; },
	};
	return node;
}

const announced = [];
const common = Object.assign({}, C, { announce(doc, msg) { announced.push(msg); } });

global.document = {
	readyState: "complete", activeElement: null,
	createElement: (tag) => fakeEl(tag),
	getElementById: () => null,
	querySelector: () => null,
	addEventListener() {}, removeEventListener() {},
	body: fakeEl("body"),
};
global.document.documentElement = global.document.body;
global.window = { frappe: { passkeys_common: common }, login: { login_handlers: {} }, addEventListener() {} };

const mod = require("../../public/js/passkey_login.bundle.js");

function lastDialog() {
	const overlay = global.document.body.appended[global.document.body.appended.length - 1];
	const root = overlay.appended[0];
	const buttons = root.querySelector(".passkey-dialog-actions").appended;
	return { root, primary: buttons.find((b) => b.className.includes("btn-primary")) };
}

function install({ credentialsGet, call }) {
	global.window.PublicKeyCredential = function () {};
	Object.defineProperty(global, "navigator", {
		value: { credentials: { get: credentialsGet } },
		configurable: true, writable: true,
	});
	global.window.frappe.call = call;
}

const OPTIONS = { challenge: "AAAA", allowCredentials: [] };
const VERIFY_FAILED = "That passkey couldn't be verified — try again.";

function lastDialogButtons() {
	const overlay = global.document.body.appended[global.document.body.appended.length - 1];
	return overlay.appended[0].querySelector(".passkey-dialog-actions").appended;
}

function notAllowed() {
	const e = new Error("cancelled");
	e.name = "NotAllowedError";
	return e;
}

test("second factor: the passkey sheet opens when the dialog does, with no click", async () => {
	let gets = 0;
	const states = [];
	install({
		credentialsGet: () => { gets += 1; return Promise.resolve({ toJSON: () => ({ id: "cred-1" }) }); },
		call: (opts) => { states.push(opts.args.state_id); opts.statusCode[200]({ message: "Logged In" }); return Promise.resolve(); },
	});
	mod.runSecondFactorCeremony("state-auto", OPTIONS, false);
	await tick(); await tick();
	assert.strictEqual(gets, 1, "get() ran before any click");
	assert.deepStrictEqual(states, ["state-auto"], "the assertion was verified without a click");
});

test("second factor: a refused or cancelled automatic sheet leaves today's dialog, silently", async () => {
	for (const name of ["NotAllowedError", "SecurityError"]) {
		let gets = 0;
		install({
			credentialsGet: () => { gets += 1; const e = notAllowed(); e.name = name; return Promise.reject(e); },
			call: () => assert.fail("no verify call after a refused sheet"),
		});
		announced.length = 0;
		const before = global.document.body.appended.length;
		mod.runSecondFactorCeremony("state-quiet", OPTIONS, true);
		const { root, primary } = lastDialog();
		await tick(); await tick();
		assert.strictEqual(gets, 1, name + ": the automatic sheet was tried");
		assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, "", name + ": no error text");
		assert.deepStrictEqual(announced, [], name + ": nothing announced for a prompt the browser may never show");
		assert.strictEqual(global.document.body.appended.length, before + 1, name + ": only this dialog opened");
		const labels = lastDialogButtons().map((b) => b.textContent);
		assert.ok(labels.includes("Use a passkey") && labels.includes("Use a verification code instead"),
			name + ": the passkey button and the code fallback stay");

		primary.click();
		await tick(); await tick();
		assert.strictEqual(gets, 2, name + ": the button opens the sheet again");
	}
});

test("second factor: a verify with no recognised status shows and announces the error once, then allows a retry", async () => {
	let verifyCalls = 0;
	install({
		credentialsGet: () => Promise.resolve({ toJSON: () => ({ id: "cred-1" }) }),
		call: () => { verifyCalls += 1; return Promise.reject(new Error("transport failure")); },
	});
	announced.length = 0;
	mod.runSecondFactorCeremony("state-1", OPTIONS, false);
	const { root, primary } = lastDialog();
	await tick(); await tick(); await tick();
	assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, VERIFY_FAILED);
	assert.strictEqual(announced.filter((m) => m === VERIFY_FAILED).length, 1, "announced exactly once");

	primary.click();
	await tick(); await tick(); await tick();
	assert.strictEqual(verifyCalls, 2, "the ceremony was released, so the retry reaches the server");
});

test("second factor: a cancelled passkey prompt after a click is shown and announced once", async () => {
	install({
		credentialsGet: () => Promise.reject(notAllowed()),
		call: () => assert.fail("no verify call after a cancelled prompt"),
	});
	mod.runSecondFactorCeremony("state-2", OPTIONS, false);
	const { root, primary } = lastDialog();
	await tick(); await tick();

	announced.length = 0;
	primary.click();
	await tick(); await tick();
	const message = root.querySelector(".passkey-dialog-error").textContent;
	assert.ok(message, "the error is painted in the dialog");
	assert.strictEqual(announced.filter((m) => m === message).length, 1, "announced exactly once");
});

test("second factor: an expired ceremony adopts the server's re-armed state for the retry", async () => {
	const states = [];
	install({
		credentialsGet: () => Promise.resolve({ toJSON: () => ({ id: "cred-1" }) }),
		call: (opts) => {
			states.push(opts.args.state_id);
			if (states.length > 1) return Promise.resolve({});
			const body = { exc_type: "CeremonyExpired", state_id: "fresh-state", verification: { options: OPTIONS } };
			opts.statusCode[401]({ responseJSON: body });
			return Promise.reject(body);
		},
	});
	mod.runSecondFactorCeremony("stale-state", OPTIONS, false);
	const { root, primary } = lastDialog();
	await tick(); await tick(); await tick();
	assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, "That didn't work — try your passkey again.");
	primary.click();
	await tick(); await tick(); await tick();
	assert.deepStrictEqual(states, ["stale-state", "fresh-state"]);
});

function deferred() {
	let resolve;
	const promise = new Promise((done) => { resolve = done; });
	return { promise, resolve };
}

function buttonLabelled(label) {
	return lastDialogButtons().find((b) => b.textContent === label);
}

test("second factor with passkey sign-in also on: the autofill request is aborted first and re-armed on close", async () => {
	const gets = [];
	install({
		credentialsGet: (options) => { gets.push(options); return new Promise(() => {}); },
		call: () => assert.fail("no verify call while the prompts are pending"),
	});
	const originalQuerySelector = global.document.querySelector;
	const emailInput = Object.assign(fakeEl("input"), { getAttribute: () => "username" });
	global.document.querySelector = (selector) => (selector === "#login_email" ? emailInput : null);
	try {
		mod.state.conditionalEnabled = true;
		mod.state.login.adopt("first-factor-state", { challenge: "AQ", allowCredentials: [] }, Date.now());
		let conditionalAborted = false;
		mod.state.conditionalAbort = { abort() { conditionalAborted = true; } };

		mod.runSecondFactorCeremony("state-both", OPTIONS, false);
		assert.strictEqual(conditionalAborted, true, "the autofill request is aborted before the second-factor one");
		await tick(); await tick();
		assert.strictEqual(gets.length, 1);
		assert.strictEqual(gets[0].mediation, undefined, "the second-factor request is the only one open");

		// A background re-begin that lands now must not start the autofill request under the dialog.
		mod.state.modes.first_factor = true;
		global.fetch = () => Promise.resolve({
			ok: true,
			json: () => Promise.resolve({ message: { enabled: true, modes: { first_factor: true, second_factor: true }, state_id: "rebegun", options: OPTIONS } }),
		});
		mod.onPageShow({ persisted: true });
		await tick(); await tick();
		assert.strictEqual(mod.state.login.stateId, "rebegun");
		assert.strictEqual(gets.length, 1, "no autofill request while the dialog is open");

		buttonLabelled("Not now").click();
		assert.strictEqual(gets[0].signal.aborted, true, "closing the dialog cancels its request");
		assert.strictEqual(gets.length, 2, "closing the dialog re-arms the autofill request");
		assert.strictEqual(gets[1].mediation, "conditional");
	} finally {
		global.document.querySelector = originalQuerySelector;
		mod.state.conditionalEnabled = false;
		mod.state.conditionalAbort = null;
		mod.state.modes.first_factor = false;
		delete global.fetch;
	}
});

test("second factor: an assertion that arrives after the dialog closed is never verified", async () => {
	const credential = deferred();
	const gets = [];
	const methods = [];
	install({
		credentialsGet: (options) => { gets.push(options); return credential.promise; },
		call: (opts) => { methods.push(opts.method); return Promise.resolve(); },
	});
	mod.runSecondFactorCeremony("state-late", OPTIONS, false);
	await tick();
	buttonLabelled("Not now").click();
	assert.strictEqual(gets[0].signal.aborted, true);
	credential.resolve({ toJSON: () => ({ id: "cred-late" }) });
	await tick(); await tick();
	assert.deepStrictEqual(methods, [], "no verify_second_factor after the user closed the dialog");
});

test("second factor: choosing the verification code cancels the request, and a late assertion is dropped", async () => {
	const credential = deferred();
	const gets = [];
	const methods = [];
	install({
		credentialsGet: (options) => { gets.push(options); return credential.promise; },
		call: (opts) => { methods.push(opts.method); return new Promise(() => {}); },
	});
	mod.runSecondFactorCeremony("state-otp", OPTIONS, true);
	await tick();
	buttonLabelled("Use a verification code instead").click();
	assert.strictEqual(gets[0].signal.aborted, true);
	credential.resolve({ toJSON: () => ({ id: "cred-late" }) });
	await tick(); await tick();
	assert.deepStrictEqual(methods, ["passkeys.passkey.fallback_to_otp"], "only the code hand-off reached the server");
});

function abortable(entry) {
	return new Promise((resolve, reject) => {
		entry.signal.addEventListener("abort", () => {
			entry.settled = true;
			const e = new Error("aborted");
			e.name = "AbortError";
			reject(e);
		});
	});
}

// Both modes on: an autofill request that the second-factor dialog pauses and re-arms.
async function withAutofill(run) {
	const originalQuerySelector = global.document.querySelector;
	const emailInput = Object.assign(fakeEl("input"), { getAttribute: () => "username" });
	global.document.querySelector = (selector) => (selector === "#login_email" ? emailInput : null);
	mod.state.conditionalEnabled = true;
	mod.state.login.adopt("first-factor-state", { challenge: "AQ", allowCredentials: [] }, Date.now());
	try {
		await run();
	} finally {
		global.document.querySelector = originalQuerySelector;
		mod.state.conditionalEnabled = false;
		mod.state.conditionalAbort = null;
		mod.state.modes.first_factor = false;
		mod.state.secondFactorOpen = false;
		delete global.fetch;
	}
}

test("second factor: while the passkey is verified the dialog says so, and Not now, Esc and the code link leave it open", async () => {
	const methods = [];
	let verify = null;
	install({
		credentialsGet: () => Promise.resolve({ toJSON: () => ({ id: "cred-1" }) }),
		call: (opts) => { methods.push(opts.method); return new Promise((resolve) => { verify = { opts, resolve }; }); },
	});
	const keyHandlers = [];
	const originalAddEventListener = global.document.addEventListener;
	global.document.addEventListener = (type, fn) => { if (type === "keydown") keyHandlers.push(fn); };
	try {
		mod.runSecondFactorCeremony("state-verifying", OPTIONS, true);
	} finally {
		global.document.addEventListener = originalAddEventListener;
	}
	const overlay = global.document.body.appended[global.document.body.appended.length - 1];
	const { root } = lastDialog();
	await tick(); await tick();
	assert.ok(verify, "verify_second_factor is in flight");
	assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, "Verifying…");
	assert.ok(lastDialogButtons().every((b) => b.disabled === true), "every button is disabled");

	buttonLabelled("Not now").click();
	keyHandlers[keyHandlers.length - 1]({ key: "Escape", preventDefault() {} });
	buttonLabelled("Use a verification code instead").click();
	assert.ok(overlay.parentNode, "the dialog stays open while the verify runs");
	assert.deepStrictEqual(methods, ["passkeys.passkey.verify_second_factor"], "no code hand-off races the verify");

	verify.opts.statusCode[429]({ responseJSON: {} });
	verify.resolve();
	await tick(); await tick();
	assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, "Too many attempts. Wait a moment, then try again.");
	assert.ok(lastDialogButtons().every((b) => b.disabled === false), "the buttons come back once the verify settles");
	buttonLabelled("Not now").click();
	assert.strictEqual(overlay.parentNode, null, "the dialog closes again");
});

test("second factor: an assertion that can't be sent leaves the dialog unlocked", async () => {
	const methods = [];
	install({
		credentialsGet: () => Promise.resolve({ toJSON: () => { throw new TypeError("bad assertion"); } }),
		call: (opts) => { methods.push(opts.method); return Promise.resolve(); },
	});
	mod.runSecondFactorCeremony("state-unsendable", OPTIONS, true);
	const overlay = global.document.body.appended[global.document.body.appended.length - 1];
	await tick(); await tick();
	assert.deepStrictEqual(methods, [], "nothing was posted");
	assert.ok(lastDialogButtons().every((b) => b.disabled !== true), "no button is left disabled");
	buttonLabelled("Not now").click();
	assert.strictEqual(overlay.parentNode, null, "Not now still closes the dialog");
});

test("second factor: keyboard focus stays in the dialog while the verify runs, and comes back after", async () => {
	let verify = null;
	install({
		credentialsGet: () => Promise.resolve({ toJSON: () => ({ id: "cred-1" }) }),
		call: (opts) => new Promise((resolve) => { verify = { opts, resolve }; }),
	});
	const keyHandlers = [];
	const originalAddEventListener = global.document.addEventListener;
	global.document.addEventListener = (type, fn) => { if (type === "keydown") keyHandlers.push(fn); };
	try {
		mod.runSecondFactorCeremony("state-focus", OPTIONS, true);
	} finally {
		global.document.addEventListener = originalAddEventListener;
	}
	const { root, primary } = lastDialog();
	const buttons = lastDialogButtons();
	// Real focus rules: a disabled button can't keep focus, and focus() moves activeElement.
	root.contains = (el) => el === root || buttons.includes(el);
	[root, ...buttons].forEach((el) => { el.focus = () => { if (!el.disabled) global.document.activeElement = el; }; });
	primary.focus();
	await tick(); await tick();
	assert.ok(verify, "verify_second_factor is in flight");
	assert.strictEqual(global.document.activeElement, root, "focus moved to the dialog, not the page");
	let tabbed = false;
	keyHandlers[keyHandlers.length - 1]({ key: "Tab", shiftKey: false, preventDefault() { tabbed = true; } });
	assert.ok(tabbed, "Tab can't leave the dialog while it is locked");

	verify.opts.statusCode[429]({ responseJSON: {} });
	verify.resolve();
	await tick(); await tick();
	assert.strictEqual(global.document.activeElement, primary, "focus returns to the button the user was on");
	global.document.activeElement = null;
	buttonLabelled("Not now").click();
});

test("second factor: Use a passkey starts nothing while the verification-code hand-off is pending", async () => {
	const gets = [];
	const methods = [];
	install({
		credentialsGet: (options) => { gets.push(options); return abortable(options); },
		call: (opts) => { methods.push(opts.method); return new Promise(() => {}); },
	});
	mod.runSecondFactorCeremony("state-handoff", OPTIONS, true);
	await tick();
	buttonLabelled("Use a verification code instead").click();
	await tick(); await tick();
	buttonLabelled("Use a passkey").click();
	await tick(); await tick();
	assert.strictEqual(gets.length, 1, "no second prompt races the hand-off for the same state");
	assert.deepStrictEqual(methods, ["passkeys.passkey.fallback_to_otp"]);
});

test("second factor: Use a passkey while the automatic prompt is pending says so and starts nothing", async () => {
	const gets = [];
	install({
		credentialsGet: (options) => { gets.push(options); return new Promise(() => {}); },
		call: () => assert.fail("no verify call while the prompt is pending"),
	});
	mod.runSecondFactorCeremony("state-pending", OPTIONS, false);
	await tick();
	announced.length = 0;
	buttonLabelled("Use a passkey").click();
	await tick();
	assert.strictEqual(gets.length, 1, "the open prompt is the only one");
	assert.deepStrictEqual(announced, ["Waiting for your passkey."]);
});

test("second factor with passkey sign-in also on: a second close re-arms nothing, and the autofill request stays abortable", async () => {
	const conditional = [];
	let handoff = null;
	install({
		credentialsGet: (options) => {
			if (options.mediation !== "conditional") return abortable(options);
			const entry = { signal: options.signal, settled: false };
			conditional.push(entry);
			return abortable(entry);
		},
		call: (opts) => new Promise(() => { handoff = opts; }),
	});
	await withAutofill(async () => {
		mod.runSecondFactorCeremony("state-twice", OPTIONS, true);
		await tick();
		buttonLabelled("Use a verification code instead").click();
		buttonLabelled("Not now").click();
		assert.strictEqual(conditional.length, 1, "closing the dialog re-arms autofill");
		// The hand-off's 401 closes the dialog a second time.
		handoff.statusCode[401]({ responseJSON: { exc_type: "CeremonyExpired" } });
		await tick(); await tick();
		assert.strictEqual(conditional.length, 1, "the second close starts no second autofill request");
		assert.strictEqual(conditional[0].settled, false);
		assert.ok(mod.state.conditionalAbort, "the autofill request keeps its controller");
		mod.state.conditionalAbort.abort(); // what a click on "Sign in with a passkey" does first
		assert.strictEqual(conditional[0].signal.aborted, true, "a click can still abort the autofill request");
	});
});

test("autofill: a request that is replaced leaves the newer one's controller in place", async () => {
	const conditional = [];
	install({
		credentialsGet: (options) => {
			const entry = { signal: options.signal, settled: false };
			if (options.mediation === "conditional") conditional.push(entry);
			return abortable(entry);
		},
		call: () => new Promise(() => {}),
	});
	await withAutofill(async () => {
		mod.state.modes.first_factor = true;
		global.fetch = () => Promise.resolve({
			ok: true,
			json: () => Promise.resolve({ message: { enabled: true, modes: { first_factor: true }, state_id: "restored", options: OPTIONS } }),
		});
		// Two page restores share one re-begin, and each re-arms: the second request replaces the first.
		mod.onPageShow({ persisted: true });
		mod.onPageShow({ persisted: true });
		await tick(); await tick(); await tick();
		assert.strictEqual(conditional.length, 2);
		assert.strictEqual(conditional[0].settled, true, "the first request was aborted");
		assert.strictEqual(conditional[1].settled, false);
		assert.ok(mod.state.conditionalAbort, "the newer request keeps its controller");
		mod.state.conditionalAbort.abort();
		assert.strictEqual(conditional[1].signal.aborted, true, "the field holds the live request's controller");
	});
});

// Fake timers for one test: the bundle's timers run only when the test moves the clock.
function useFakeTimers() {
	let now = 0;
	const pending = new Set();
	const saved = [global.setTimeout, global.clearTimeout];
	global.setTimeout = (fn, ms) => { const timer = { fn, at: now + (ms || 0) }; pending.add(timer); return timer; };
	global.clearTimeout = (timer) => { pending.delete(timer); };
	return {
		advance(ms) {
			now += ms;
			for (const timer of [...pending].sort((a, b) => a.at - b.at)) {
				if (timer.at > now) continue;
				pending.delete(timer);
				timer.fn();
			}
		},
		restore() { [global.setTimeout, global.clearTimeout] = saved; },
	};
}

// A request the server hasn't answered: the test settles it with entry.reject, and abort() rejects
// it the way jQuery's jqXHR does.
function stalledCall(calls) {
	return (opts) => {
		const entry = { method: opts.method, opts, aborted: 0 };
		calls.push(entry);
		const promise = new Promise((resolve, reject) => { entry.reject = reject; });
		promise.abort = () => { entry.aborted += 1; entry.reject(Object.assign(new Error("abort"), { statusText: "abort" })); };
		return promise;
	};
}

// Opens a dialog and returns its Esc handler.
function openCapturingKeys(open) {
	const keyHandlers = [];
	const originalAddEventListener = global.document.addEventListener;
	global.document.addEventListener = (type, fn) => { if (type === "keydown") keyHandlers.push(fn); };
	try {
		open();
	} finally {
		global.document.addEventListener = originalAddEventListener;
	}
	const handler = keyHandlers[keyHandlers.length - 1];
	return () => handler({ key: "Escape", preventDefault() {} });
}

// A signed-in browser per Frappe's readable user_id cookie, and a page reload counter.
function withSessionCookie(run) {
	const cookies = {};
	const reloads = { count: 0 };
	global.window.frappe.get_cookie = (name) => cookies[name];
	global.window.location = { reload() { reloads.count += 1; } };
	return Promise.resolve(run(cookies, reloads)).finally(() => {
		delete global.window.frappe.get_cookie;
		delete global.window.location;
	});
}

const TOO_LONG = "Verifying took too long. Try again.";

test("second factor: a verify with no answer is aborted after 30 seconds, and the dialog says so and unlocks", async () => {
	const clock = useFakeTimers();
	const calls = [];
	let gets = 0;
	try {
		install({ credentialsGet: () => { gets += 1; return Promise.resolve({ toJSON: () => ({ id: "cred-1" }) }); }, call: stalledCall(calls) });
		const pressEscape = openCapturingKeys(() => mod.runSecondFactorCeremony("state-stalled", OPTIONS, true));
		const overlay = global.document.body.appended[global.document.body.appended.length - 1];
		const { root } = lastDialog();
		await tick(); await tick();
		assert.strictEqual(calls.length, 1, "verify_second_factor is in flight");
		assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, "Verifying…");

		buttonLabelled("Not now").click();
		pressEscape();
		buttonLabelled("Use a passkey").click();
		clock.advance(29999);
		assert.ok(overlay.parentNode, "a close during the verify leaves the dialog open");
		assert.strictEqual(calls[0].aborted, 0, "still waiting just before the limit");
		assert.ok(lastDialogButtons().every((b) => b.disabled === true));

		announced.length = 0;
		clock.advance(1);
		assert.strictEqual(calls[0].aborted, 1, "the request is aborted at the limit");
		assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, TOO_LONG);
		assert.deepStrictEqual(announced, [TOO_LONG], "announced once");
		assert.ok(lastDialogButtons().every((b) => b.disabled === false), "the dialog unlocks");
		await tick(); await tick();
		assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, TOO_LONG, "the aborted request's failure doesn't replace it");

		buttonLabelled("Use a passkey").click();
		await tick(); await tick();
		assert.strictEqual(gets, 2, "Use a passkey tries again");
		assert.strictEqual(calls.length, 2);
		clock.advance(30000);
		pressEscape();
		assert.strictEqual(overlay.parentNode, null, "Esc closes it once it is unlocked");
	} finally {
		clock.restore();
	}
});

test("second factor: a sign-in that lands despite the time limit takes the page in", async () => {
	const clock = useFakeTimers();
	try {
		await withSessionCookie(async (cookies, reloads) => {
			const calls = [];
			install({ credentialsGet: () => Promise.resolve({ toJSON: () => ({ id: "cred-1" }) }), call: stalledCall(calls) });

			// Signed in by the time the limit is reached: follow it, don't offer a retry.
			mod.runSecondFactorCeremony("state-late-1", OPTIONS, true);
			const first = lastDialog().root;
			await tick(); await tick();
			cookies.user_id = "user@example.com";
			clock.advance(30000);
			assert.strictEqual(calls[0].aborted, 1);
			assert.strictEqual(reloads.count, 1, "the page reloads into the signed-in session");
			assert.strictEqual(first.querySelector(".passkey-dialog-error").textContent, "Verifying…", "no time-limit message");
			assert.ok(lastDialogButtons().every((b) => b.disabled === true), "nothing to click while the page reloads");

			// Signed in only after the limit: the next action follows it instead of closing.
			cookies.user_id = "Guest";
			mod.runSecondFactorCeremony("state-late-2", OPTIONS, true);
			const overlay = global.document.body.appended[global.document.body.appended.length - 1];
			await tick(); await tick();
			clock.advance(30000);
			assert.strictEqual(lastDialog().root.querySelector(".passkey-dialog-error").textContent, TOO_LONG);
			cookies.user_id = "user@example.com";
			buttonLabelled("Not now").click();
			assert.strictEqual(reloads.count, 2, "Not now follows the sign-in");
			assert.ok(overlay.parentNode, "and doesn't just close the dialog");
		});
	} finally {
		clock.restore();
		mod.state.secondFactorOpen = false;
	}
});

// The uv-setup dialog opens from a passwordless verify the server answers with UVSetupRequired.
function openUvSetupDialog(calls) {
	const stalled = stalledCall(calls);
	install({
		credentialsGet: () => assert.fail("no passkey prompt in the uv-setup dialog"),
		call: (opts) => {
			if (opts.method !== "passkeys.passkey.verify_login") return stalled(opts);
			const body = { exc_type: "UVSetupRequired", setup_id: "uvs-1" };
			opts.statusCode[401]({ responseJSON: body });
			return Promise.reject(body);
		},
	});
	const pressEscape = openCapturingKeys(() => mod.runVerify({ toJSON: () => ({ id: "cred-1" }) }, { source: "button" }, "first-factor-state"));
	const overlay = global.document.body.appended[global.document.body.appended.length - 1];
	const { root, primary } = lastDialog();
	assert.strictEqual(primary.textContent, "Confirm", "the uv-setup dialog is open");
	root.querySelector("#passkey-uv-pwd").value = "secret";
	return { overlay, root, primary, pressEscape };
}

test("uv setup: Not now, Esc and a second Confirm do nothing while the password is checked; after 30 seconds it is aborted and the dialog unlocks", async () => {
	const clock = useFakeTimers();
	const calls = [];
	try {
		const { overlay, root, primary, pressEscape } = openUvSetupDialog(calls);
		primary.click();
		const setup = calls.filter((c) => c.method === "passkeys.passkey.complete_uv_setup");
		assert.strictEqual(setup.length, 1);
		assert.deepStrictEqual(setup[0].opts.args, { setup_id: "uvs-1", pwd: "secret" });
		assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, "Verifying…");
		assert.ok(lastDialogButtons().every((b) => b.disabled === true), "every button is disabled");

		buttonLabelled("Not now").click();
		pressEscape();
		primary.click();
		clock.advance(29999);
		assert.ok(overlay.parentNode, "a close during the check leaves the dialog open");
		assert.strictEqual(calls.length, 1, "a second Confirm sends nothing");
		assert.strictEqual(setup[0].aborted, 0);

		clock.advance(1);
		assert.strictEqual(setup[0].aborted, 1, "the request is aborted at the limit");
		assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, TOO_LONG);
		assert.ok(lastDialogButtons().every((b) => b.disabled === false), "the dialog unlocks");
		await tick(); await tick();
		assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, TOO_LONG);

		buttonLabelled("Not now").click();
		assert.strictEqual(overlay.parentNode, null, "Not now closes it once it is unlocked");
	} finally {
		clock.restore();
	}
});

test("uv setup: a wrong password unlocks the dialog and says so", async () => {
	let corePainted = 0;
	global.window.login.login_handlers[401] = () => { corePainted += 1; };
	const calls = [];
	try {
		const { root, primary } = openUvSetupDialog(calls);
		corePainted = 0;
		primary.click();
		const setup = calls[0];
		setup.opts.statusCode[401]({ responseJSON: { exc_type: "AuthenticationError" } });
		setup.reject({ status: 401 });
		await tick(); await tick();
		assert.strictEqual(corePainted, 1, "core painted its own 401");
		assert.strictEqual(root.querySelector(".passkey-dialog-error").textContent, "That didn't work — check your password and try again.");
		assert.ok(lastDialogButtons().every((b) => b.disabled === false), "the dialog unlocks");
		buttonLabelled("Not now").click();
	} finally {
		delete global.window.login.login_handlers[401];
	}
});
