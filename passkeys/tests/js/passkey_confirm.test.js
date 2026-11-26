// passkey_confirm.test.js — dependency-free unit harness for the PURE
// action-confirmation logic in passkey_common.bundle.js::createConfirmEngine + helpers.
// Runs WITHOUT the bench and WITHOUT jsdom:  node --test passkeys/tests/js
//
// Covers: 401 contract parsing (exc_type match only), grant-header build,
// signature dedupe, capability parsing, grant extraction (message-wrapped),
// the full begin->gesture->verify->grant happy path, the frappe.passkeys.call
// 401 retry + VERBATIM payload_fingerprint echo + grant-header attach,
// params/payload_hash mutual exclusion, password-fallback leg, fallback_unavailable,
// user-cancel mapping, DOMException mapping through the gesture, single-retry cap,
// concurrent-invocation dialog sharing, the opt-in passkey prompt opening with the dialog, and
// a close the controller reports through cancel(), before or after the pick, or with password only.

const test = require("node:test");
const assert = require("node:assert");
const C = require("../../public/js/passkey_common.bundle.js");

// ------------------------------------------------------------- test doubles
// A scripted `post` that records every call and returns queued responses keyed
// by method. Each queue entry is {ok, status, body}.
function makePost(script) {
	const calls = [];
	function post(method, body, headers) {
		calls.push({ method, body, headers: headers || {} });
		const q = script[method];
		const resp = Array.isArray(q) ? q.shift() : q;
		if (resp === undefined) return Promise.reject(new Error("network"));
		if (resp instanceof Error) return Promise.reject(resp);
		return Promise.resolve(resp);
	}
	post.calls = calls;
	return post;
}

// A `ui` controller double: auto-chooses a method and supplies a password.
function makeUI(opts) {
	opts = opts || {};
	const events = [];
	function factory() {
		return {
			chooseMethod(info) {
				events.push(["choose", info]);
				if (opts.cancel) return Promise.reject(new C.ConfirmError(C.CONFIRM_CODES.USER_CANCELLED, "x"));
				return Promise.resolve(opts.method || "passkey");
			},
			collectPassword(info) {
				events.push(["password", info]);
				if (opts.cancelPassword) return Promise.reject(new C.ConfirmError(C.CONFIRM_CODES.USER_CANCELLED, "x"));
				const pw = Array.isArray(opts.passwords) ? opts.passwords.shift() : opts.password;
				return Promise.resolve(pw || "hunter2");
			},
			announce(m) { events.push(["announce", m]); },
			busy(b) { events.push(["busy", b]); },
			passwordError(m) { events.push(["pwerror", m]); },
			done(ok) { events.push(["done", ok]); },
			close() { events.push(["close"]); },
			_events: events,
		};
	}
	factory.events = events;
	return factory;
}

const REQ_OPTIONS = { challenge: "abc", rpId: "example.com", userVerification: "required", allowCredentials: [] };
const ASSERTION = { id: "cred1", type: "public-key", response: {} };

// -------------------------------------------------------- helper unit tests

test("parseConfirmationRequired matches exc_type ONLY", () => {
	const body = { exc_type: "PasskeyConfirmationRequired", action: "a.b", payload_fingerprint: "ff", methods: ["passkey", "password"] };
	const got = C.parseConfirmationRequired(body);
	assert.deepStrictEqual(got, {
		action: "a.b", payloadFingerprint: "ff", methods: ["passkey", "password"],
		actionLabel: null, parameterSummary: null,
	});
	assert.strictEqual(C.parseConfirmationRequired({ exc_type: "SomethingElse" }), null);
	assert.strictEqual(C.parseConfirmationRequired({ action: "a.b" }), null); // no exc_type
	assert.strictEqual(C.parseConfirmationRequired(null), null);
});

test("buildGrantHeaders uses the pinned header name (mirrors session.py)", () => {
	assert.deepStrictEqual(C.buildGrantHeaders("tok"), { "X-Passkey-Grant": "tok" });
	assert.deepStrictEqual(C.buildGrantHeaders(""), {}); // no empty token
	assert.strictEqual(C.GRANT_HEADER, "X-Passkey-Grant");
});

test("confirmSignature: identical params dedupe; fingerprint path distinct", () => {
	const a = C.confirmSignature("act", { b: 2, a: 1 });
	const b = C.confirmSignature("act", { a: 1, b: 2 });
	assert.strictEqual(a, b, "key order must not matter");
	assert.notStrictEqual(a, C.confirmSignature("act", { a: 1 }));
	assert.strictEqual(C.confirmSignature("act", null, "fp1"), "fp:act:fp1");
});

test("confirmCapabilities parses the methods enum", () => {
	assert.deepStrictEqual(C.confirmCapabilities(["passkey", "sudo"]), { passkey: true, password: false, sudo: true });
	assert.deepStrictEqual(C.confirmCapabilities([]), { passkey: false, password: false, sudo: false });
	assert.deepStrictEqual(C.confirmCapabilities(undefined), { passkey: false, password: false, sudo: false });
});

test("extractGrant reads the message-wrapped {grant}", () => {
	assert.strictEqual(C.extractGrant({ message: { grant: "g1" } }), "g1");
	assert.strictEqual(C.extractGrant({ grant: "g2" }), "g2");
	assert.strictEqual(C.extractGrant({ message: {} }), null);
});

test("confirmationActionContext humanizes actions and bounds safe server summaries", () => {
	assert.deepStrictEqual(C.confirmationActionContext("passkeys.manage", null, null), {
		label: "Manage passkeys", labelFromServer: false, summary: [],
	});
	const context = C.confirmationActionContext("custom.release_payment", "Release payment", {
		Payment: "PAY-1",
		Nested: { secret: "drop" },
		Markup: "<img src=x onerror=alert(1)>",
	});
	assert.strictEqual(context.label, "Release payment");
	assert.strictEqual(context.labelFromServer, true);
	assert.deepStrictEqual(context.summary, [
		{ label: "Payment", value: "PAY-1" },
		{ label: "Markup", value: "<img src=x onerror=alert(1)>" },
	]);
});

// ------------------------------------------------------- engine flow tests

test("confirm(): begin(params) -> gesture -> verify -> grant token", async () => {
	const post = makePost({
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s1", options: REQ_OPTIONS, payload_fingerprint: "fp1", methods: ["passkey", "password"] } } }],
		"passkeys.confirm.verify_confirmation": [{ ok: true, status: 200, body: { message: { grant: "GRANT-1" } } }],
	});
	let gestureOpts = null;
	const engine = C.createConfirmEngine({
		post,
		runGesture: (o) => { gestureOpts = o; return Promise.resolve(ASSERTION); },
		ui: makeUI({ method: "passkey" }),
	});
	const grant = await engine.confirm("myapp.release_payment", { payment_id: "PAY-1" });
	assert.strictEqual(grant, "GRANT-1");
	// begin got RAW params, never a hash
	assert.deepStrictEqual(post.calls[0].body, { action: "myapp.release_payment", params: { payment_id: "PAY-1" } });
	assert.ok(!("payload_hash" in post.calls[0].body));
	// gesture ran on the server options; verify posted the assertion + state_id
	assert.strictEqual(gestureOpts, REQ_OPTIONS);
	assert.deepStrictEqual(post.calls[1], { method: "passkeys.confirm.verify_confirmation", body: { state_id: "s1", credential: ASSERTION }, headers: {} });
});

test("call(): 401 -> echo payload_fingerprint VERBATIM -> confirm -> retry with grant header", async () => {
	const post = makePost({
		"myapp.api.release_payment": [
			{ ok: false, status: 401, body: { exc_type: "PasskeyConfirmationRequired", action: "myapp.release_payment", payload_fingerprint: "SERVER-FP", methods: ["passkey"] } },
			{ ok: true, status: 200, body: { message: "done" } },
		],
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s2", options: REQ_OPTIONS, payload_fingerprint: "SERVER-FP", methods: ["passkey"] } } }],
		"passkeys.confirm.verify_confirmation": [{ ok: true, status: 200, body: { message: { grant: "GRANT-2" } } }],
	});
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI({ method: "passkey" }) });
	const result = await engine.call("myapp.api.release_payment", { payment_id: "PAY-2" });
	assert.strictEqual(result, "done");
	// begin echoed the fingerprint verbatim as payload_hash, and sent NO params (mutual exclusion)
	const beginCall = post.calls.find((c) => c.method === "passkeys.confirm.begin_confirmation");
	assert.deepStrictEqual(beginCall.body, { action: "myapp.release_payment", payload_hash: "SERVER-FP" });
	assert.ok(!("params" in beginCall.body));
	// the retry attached the grant header
	const retry = post.calls.filter((c) => c.method === "myapp.api.release_payment")[1];
	assert.deepStrictEqual(retry.headers, { "X-Passkey-Grant": "GRANT-2" });
});

test("call(): protected-action display metadata survives an empty begin response", async () => {
	const post = makePost({
		"myapp.api.release_payment": [
			{ ok: false, status: 401, body: {
				exc_type: "PasskeyConfirmationRequired", action: "myapp.release_payment",
				payload_fingerprint: "SERVER-FP", methods: ["passkey"],
				action_label: "Release payment", parameter_summary: [{ label: "Payment", value: "PAY-7" }],
			} },
			{ ok: true, status: 200, body: { message: "done" } },
		],
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: {
			state_id: "s", options: REQ_OPTIONS, payload_fingerprint: "SERVER-FP",
			methods: ["passkey"], action_label: null, parameter_summary: [],
		} } }],
		"passkeys.confirm.verify_confirmation": [{ ok: true, status: 200, body: { message: { grant: "G" } } }],
	});
	const ui = makeUI({ method: "passkey" });
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui });
	await engine.call("myapp.api.release_payment", { payment_id: "PAY-7" });
	const { cancel, ...choice } = ui.events.find((event) => event[0] === "choose")[1];
	assert.deepStrictEqual(choice, {
		action: "myapp.release_payment", actionLabel: "Release payment",
		parameterSummary: [{ label: "Payment", value: "PAY-7" }],
		canPasskey: true, canPassword: false,
	});
	assert.strictEqual(typeof cancel, "function");
});

test("call(): non-401 success passes through unwrapped, no confirmation", async () => {
	const post = makePost({ "myapp.ping": [{ ok: true, status: 200, body: { message: { ok: 1 } } }] });
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.reject(new Error("should not run")), ui: makeUI() });
	const r = await engine.call("myapp.ping", {});
	assert.deepStrictEqual(r, { ok: 1 });
});

test("call(): retry that still 401s rejects confirmation_failed (single retry)", async () => {
	const post = makePost({
		"myapp.api.x": [
			{ ok: false, status: 401, body: { exc_type: "PasskeyConfirmationRequired", action: "myapp.x", payload_fingerprint: "fp", methods: ["passkey"] } },
			{ ok: false, status: 401, body: { exc_type: "PasskeyConfirmationRequired", action: "myapp.x", payload_fingerprint: "fp", methods: ["passkey"] } },
		],
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, payload_fingerprint: "fp", methods: ["passkey"] } } }],
		"passkeys.confirm.verify_confirmation": [{ ok: true, status: 200, body: { message: { grant: "G" } } }],
	});
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI({ method: "passkey" }) });
	await assert.rejects(engine.call("myapp.api.x", {}), (e) => e.code === C.CONFIRM_CODES.CONFIRMATION_FAILED);
	// exactly two attempts on the wrapped method — never an infinite retry loop
	assert.strictEqual(post.calls.filter((c) => c.method === "myapp.api.x").length, 2);
});

test("password fallback leg mints a grant via reauth_password (action-bound)", async () => {
	const post = makePost({
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: {
			state_id: "s", options: REQ_OPTIONS, payload_fingerprint: "fp9", methods: ["password"],
			action_label: "Release payment", parameter_summary: { Payment: "PAY-1" },
		} } }],
		"passkeys.confirm.reauth_password": [{ ok: true, status: 200, body: { message: { grant: "PW-GRANT" } } }],
	});
	const ui = makeUI({ method: "password", password: "s3cret" });
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.reject(new Error("no gesture")), ui });
	const grant = await engine.confirm("myapp.pay", { id: 1 });
	assert.strictEqual(grant, "PW-GRANT");
	const rc = post.calls.find((c) => c.method === "passkeys.confirm.reauth_password");
	// reauth carries action + fingerprint so the server can mint an ACTION grant (not a bare sudo seed)
	assert.deepStrictEqual(rc.body, { pwd: "s3cret", action: "myapp.pay", payload_fingerprint: "fp9" });
	const { cancel, ...context } = ui.events.find((event) => event[0] === "password")[1];
	assert.deepStrictEqual(context, {
		action: "myapp.pay", actionLabel: "Release payment", parameterSummary: { Payment: "PAY-1" },
	});
	assert.strictEqual(typeof cancel, "function");
});

test("password fallback: wrong password retries in-dialog, then succeeds", async () => {
	const post = makePost({
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, payload_fingerprint: "fp", methods: ["password"] } } }],
		"passkeys.confirm.reauth_password": [
			{ ok: false, status: 401, body: {} },
			{ ok: true, status: 200, body: { message: { grant: "OK" } } },
		],
	});
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.reject(new Error()), ui: makeUI({ method: "password", passwords: ["wrong", "right"] }) });
	const grant = await engine.confirm("myapp.pay", {});
	assert.strictEqual(grant, "OK");
	assert.strictEqual(post.calls.filter((c) => c.method === "passkeys.confirm.reauth_password").length, 2);
});

test("no method available -> fallback_unavailable", async () => {
	const post = makePost({
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, methods: [] } } }],
	});
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI() });
	await assert.rejects(engine.confirm("myapp.x", {}), (e) => e.code === C.CONFIRM_CODES.FALLBACK_UNAVAILABLE);
});

test("user cancels the dialog -> user_cancelled", async () => {
	const post = makePost({
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, methods: ["passkey", "password"] } } }],
	});
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI({ cancel: true }) });
	await assert.rejects(engine.confirm("myapp.x", {}), (e) => e.code === C.CONFIRM_CODES.USER_CANCELLED);
});

test("gesture DOMException maps through the taxonomy (NotAllowedError -> user_cancelled)", async () => {
	const post = makePost({
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, methods: ["passkey"] } } }],
	});
	const err = new Error("cancelled"); err.name = "NotAllowedError";
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.reject(err), ui: makeUI({ method: "passkey" }) });
	await assert.rejects(engine.confirm("myapp.x", {}), (e) => e.code === C.CONFIRM_CODES.USER_CANCELLED);
});

test("begin 417 (served-by-core) -> not_supported", async () => {
	const post = makePost({
		"passkeys.confirm.begin_confirmation": [{ ok: false, status: 417, body: { exc_type: "PasskeyServedByCore" } }],
	});
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI() });
	await assert.rejects(engine.confirm("myapp.x", {}), (e) => e.code === C.CONFIRM_CODES.NOT_SUPPORTED);
});

test("begin refused with a server message (impersonated session) -> confirmation_failed with that message", async () => {
	const message = "Passkeys can't be changed or used while impersonating a user.";
	const post = makePost({
		"passkeys.confirm.begin_confirmation": [{
			ok: false, status: 403,
			body: { exc_type: "ImpersonatedSessionRefused", _server_messages: JSON.stringify([JSON.stringify({ message })]) },
		}],
	});
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.reject(new Error("should not run")), ui: makeUI() });
	await assert.rejects(engine.confirm("myapp.x", {}),
		(e) => e.code === C.CONFIRM_CODES.CONFIRMATION_FAILED && e.message === message);
});

test("concurrency (A44): identical concurrent confirms share ONE ceremony", async () => {
	let beginCount = 0;
	const post = function (method, body) {
		if (method === "passkeys.confirm.begin_confirmation") {
			beginCount += 1;
			return Promise.resolve({ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, payload_fingerprint: "fp", methods: ["passkey"] } } });
		}
		return Promise.resolve({ ok: true, status: 200, body: { message: { grant: "G" } } });
	};
	post.calls = [];
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI({ method: "passkey" }) });
	const [a, b] = await Promise.all([
		engine.confirm("myapp.pay", { id: 7 }),
		engine.confirm("myapp.pay", { id: 7 }),
	]);
	assert.strictEqual(a, "G");
	assert.strictEqual(b, "G");
	assert.strictEqual(beginCount, 1, "identical concurrent confirms must not start two ceremonies");
});

// ---------------------------------------- the passkey prompt opening with the dialog
// Opt-in (promptWithDialog): once the dialog has painted, and only when the user's own click led
// here, the engine starts the gesture itself. A refused or dismissed prompt is silent and leaves
// the dialog's choices; a passkey pick joins an open prompt; a password pick or a cancel aborts it.
// Without the option the gesture waits for the pick, as before.

function deferred() {
	let resolve, reject;
	const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
	return { promise, resolve, reject };
}
const flush = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r)); };

// The browser seams the engine reads: user activation and the next frame.
const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
let frames = [];
function browser({ activation = true } = {}) {
	Object.defineProperty(globalThis, "navigator", {
		configurable: true, writable: true,
		value: activation === null ? {} : { userActivation: { isActive: activation } },
	});
	frames = [];
	globalThis.requestAnimationFrame = (cb) => { frames.push(cb); return frames.length; };
}
// Runs the pending frames, then the task each one queued for after its paint.
async function paint() {
	await flush();
	frames.splice(0).forEach((cb) => cb());
	await new Promise((r) => setTimeout(r, 5));
	await flush();
}
test.afterEach(() => {
	delete globalThis.requestAnimationFrame;
	if (originalNavigator) Object.defineProperty(globalThis, "navigator", originalNavigator);
	else delete globalThis.navigator;
});

function sheetScript(extra) {
	return Object.assign({
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, payload_fingerprint: "fp", methods: ["passkey", "password"] } } }],
		"passkeys.confirm.verify_confirmation": [{ ok: true, status: 200, body: { message: { grant: "SHEET-GRANT" } } }],
	}, extra);
}

// A dialog double whose method choice resolves only when the test picks.
function makeWaitingUI() {
	const events = [];
	const choice = deferred();
	const controller = {
		chooseMethod(info) { events.push(["choose", info]); return choice.promise; },
		collectPassword(info) { events.push(["password", info]); return Promise.resolve("hunter2"); },
		announce(m) { events.push(["announce", m]); },
		busy(b) { events.push(["busy", b]); },
		passwordError(m) { events.push(["pwerror", m]); },
		done(ok) { events.push(["done", ok]); },
	};
	return { controller, events, pick: choice.resolve, cancel: () => choice.reject(new C.ConfirmError(C.CONFIRM_CODES.USER_CANCELLED, "x")) };
}

function promptEngine(post, ui, runGesture) {
	return C.createConfirmEngine({ post, runGesture, ui: () => ui.controller, promptWithDialog: true });
}

test("without promptWithDialog no gesture starts before the pick", async () => {
	browser();
	const post = makePost(sheetScript());
	const ui = makeWaitingUI();
	const gestures = [];
	const engine = C.createConfirmEngine({ post, runGesture: (...args) => { gestures.push(args); return Promise.resolve(ASSERTION); }, ui: () => ui.controller });
	const grant = engine.confirm("myapp.pay", { id: 1 });
	await paint();
	assert.strictEqual(gestures.length, 0, "the prompt waits for the dialog's button");
	ui.pick("passkey");
	assert.strictEqual(await grant, "SHEET-GRANT");
	assert.strictEqual(gestures.length, 1, "one gesture");
	assert.strictEqual(gestures[0][0], REQ_OPTIONS);
	assert.ok(gestures[0][1].signal instanceof AbortSignal, "the picked gesture gets {signal} too");
	assert.deepStrictEqual(ui.events.map((e) => e[0]), ["choose", "busy", "announce", "done"], "busy comes before the gesture");
});

test("promptWithDialog: the prompt opens after the dialog has painted, and its grant needs no click", async () => {
	browser();
	const post = makePost(sheetScript());
	const ui = makeWaitingUI();
	const gestures = [];
	const engine = promptEngine(post, ui, (...args) => { gestures.push(args); return Promise.resolve(ASSERTION); });
	const grant = engine.confirm("myapp.pay", { id: 1 });
	await flush();
	await new Promise((r) => setTimeout(r, 5));
	assert.strictEqual(ui.events.length, 1, "the dialog was shown");
	assert.strictEqual(gestures.length, 0, "no prompt before the dialog's frame");
	await paint();
	assert.strictEqual(gestures.length, 1, "the gesture started without a pick");
	assert.strictEqual(gestures[0][0], REQ_OPTIONS);
	assert.ok(gestures[0][1].signal instanceof AbortSignal, "runGesture gets {signal}");
	assert.strictEqual(await grant, "SHEET-GRANT");
	assert.deepStrictEqual(ui.events.map((e) => e[0]), ["choose", "busy", "announce", "done"], "the dialog showed first, then closed");
	assert.deepStrictEqual(ui.events[ui.events.length - 1], ["done", true]);
});

test("promptWithDialog: no automatic prompt without the user's activation, or without the API", async () => {
	for (const [activation, before] of [[true, 1], [false, 0], [null, 0]]) {
		browser({ activation });
		const post = makePost(sheetScript());
		const ui = makeWaitingUI();
		const sheet = deferred();
		let gestures = 0;
		const engine = promptEngine(post, ui, () => { gestures += 1; return gestures === 1 && before ? sheet.promise : Promise.resolve(ASSERTION); });
		const grant = engine.confirm("myapp.pay", { id: 1 });
		await paint();
		assert.strictEqual(gestures, before, `activation ${activation}: ${before ? "the prompt opened" : "the dialog waits for its button"}`);
		ui.pick("passkey");
		sheet.resolve(ASSERTION);
		assert.strictEqual(await grant, "SHEET-GRANT");
		assert.strictEqual(gestures, 1, "one gesture either way");
	}
});

test("promptWithDialog: a choice made before the dialog painted starts no prompt", async () => {
	browser();
	const post = makePost(sheetScript({
		"passkeys.confirm.reauth_password": [{ ok: true, status: 200, body: { message: { grant: "PW-GRANT" } } }],
	}));
	let gestures = 0;
	const controller = {
		chooseMethod() { return "password"; }, // a dialog that remembers "use my password"
		collectPassword() { return Promise.resolve("hunter2"); },
		announce() {}, busy() {}, passwordError() {}, done() {},
	};
	const engine = C.createConfirmEngine({ post, runGesture: () => { gestures += 1; return Promise.resolve(ASSERTION); }, ui: () => controller, promptWithDialog: true });
	const grant = engine.confirm("myapp.pay", { id: 1 });
	await paint();
	assert.strictEqual(await grant, "PW-GRANT");
	assert.strictEqual(gestures, 0, "chooseMethod had settled, so no prompt opened");
});

test("promptWithDialog: a refused or dismissed prompt is silent; the passkey button runs a fresh gesture on the same ceremony", async () => {
	browser();
	const post = makePost(sheetScript());
	const ui = makeWaitingUI();
	const gestures = [];
	const err = new Error("cancelled"); err.name = "NotAllowedError";
	const engine = promptEngine(post, ui, (o) => { gestures.push(o); return gestures.length === 1 ? Promise.reject(err) : Promise.resolve(ASSERTION); });
	let settled = null;
	const grant = engine.confirm("myapp.pay", { id: 1 });
	grant.then((g) => { settled = g; }, (e) => { settled = e; });
	await paint();
	assert.strictEqual(gestures.length, 1, "the automatic prompt opened");
	assert.strictEqual(settled, null, "the refused prompt neither rejects nor closes the dialog");
	assert.deepStrictEqual(ui.events.map((e) => e[0]), ["choose"], "no error, no busy state, no message");

	ui.pick("passkey");
	assert.strictEqual(await grant, "SHEET-GRANT");
	assert.strictEqual(gestures.length, 2);
	assert.strictEqual(gestures[1], REQ_OPTIONS, "the same begin_confirmation options");
	assert.strictEqual(post.calls.filter((c) => c.method === "passkeys.confirm.begin_confirmation").length, 1);
});

test("promptWithDialog: after a refused prompt the password choice still works", async () => {
	browser();
	const post = makePost(sheetScript({
		"passkeys.confirm.reauth_password": [{ ok: true, status: 200, body: { message: { grant: "PW-GRANT" } } }],
	}));
	const ui = makeWaitingUI();
	const err = new Error("cancelled"); err.name = "NotAllowedError";
	let gestures = 0;
	const engine = promptEngine(post, ui, () => { gestures += 1; return Promise.reject(err); });
	const grant = engine.confirm("myapp.pay", { id: 1 });
	await paint();
	assert.strictEqual(gestures, 1, "the automatic prompt opened and was refused");
	ui.pick("password");
	assert.strictEqual(await grant, "PW-GRANT");
	assert.strictEqual(gestures, 1);
	assert.ok(!post.calls.some((c) => c.method === "passkeys.confirm.verify_confirmation"));
});

test("promptWithDialog: a passkey pick while the prompt is open joins it: one gesture", async () => {
	browser();
	const post = makePost(sheetScript());
	const ui = makeWaitingUI();
	const sheet = deferred();
	const signals = [];
	const engine = promptEngine(post, ui, (o, opts) => { signals.push(opts.signal); return sheet.promise; });
	const grant = engine.confirm("myapp.pay", { id: 1 });
	await paint();
	assert.strictEqual(signals.length, 1, "the automatic prompt is open before the pick");
	ui.pick("passkey");
	await flush();
	assert.deepStrictEqual(ui.events.map((e) => e[0]), ["choose", "busy", "announce"], "the pick shows the busy state under the open prompt");
	sheet.resolve(ASSERTION);
	assert.strictEqual(await grant, "SHEET-GRANT");
	assert.strictEqual(signals.length, 1);
	assert.strictEqual(signals[0].aborted, false);
});

test("promptWithDialog: a password pick while the prompt is open aborts it", async () => {
	browser();
	const post = makePost(sheetScript({
		"passkeys.confirm.reauth_password": [{ ok: true, status: 200, body: { message: { grant: "PW-GRANT" } } }],
	}));
	const ui = makeWaitingUI();
	const sheet = deferred();
	const signals = [];
	const engine = promptEngine(post, ui, (o, opts) => { signals.push(opts.signal); return sheet.promise; });
	const grant = engine.confirm("myapp.pay", { id: 1 });
	await paint();
	assert.strictEqual(signals.length, 1);
	ui.pick("password");
	assert.strictEqual(await grant, "PW-GRANT");
	assert.strictEqual(signals[0].aborted, true, "the open prompt was cancelled");
	sheet.resolve(ASSERTION);
	await flush();
	assert.ok(!post.calls.some((c) => c.method === "passkeys.confirm.verify_confirmation"));
});

test("promptWithDialog: closing the dialog while the prompt is open aborts it, and a late assertion is never verified", async () => {
	browser();
	const post = makePost(sheetScript());
	const ui = makeWaitingUI();
	const sheet = deferred();
	const signals = [];
	const engine = promptEngine(post, ui, (o, opts) => { signals.push(opts.signal); return sheet.promise; });
	const grant = engine.confirm("myapp.pay", { id: 1 });
	await paint();
	assert.strictEqual(signals.length, 1, "the automatic prompt is open before the cancel");
	ui.cancel();
	await assert.rejects(grant, (e) => e.code === C.CONFIRM_CODES.USER_CANCELLED);
	assert.strictEqual(signals[0].aborted, true, "the cancel aborted the prompt");
	sheet.resolve(ASSERTION);
	await flush();
	assert.ok(!post.calls.some((c) => c.method === "passkeys.confirm.verify_confirmation"), "fail closed");
});

// After the pick, the dialog reports its close through chooseMethod's cancel().
const closeDialog = (ui) => ui.events.find((e) => e[0] === "choose")[1].cancel();

test("closing the dialog after a passkey pick aborts the prompt, sends no verify and rejects user_cancelled", async () => {
	// [promptWithDialog, activation]: a plain pick, a pick with the option, a pick that joins the automatic prompt.
	for (const [promptWithDialog, activation] of [[false, false], [true, false], [true, true]]) {
		browser({ activation });
		const post = makePost(sheetScript());
		const ui = makeWaitingUI();
		const sheet = deferred();
		const signals = [];
		// This gesture ignores its signal, so an assertion still arrives after the close.
		const engine = C.createConfirmEngine({ post, runGesture: (o, opts) => { signals.push(opts.signal); return sheet.promise; }, ui: () => ui.controller, promptWithDialog });
		const grant = engine.confirm("myapp.pay", { id: 1 });
		await paint();
		ui.pick("passkey");
		await flush();
		assert.strictEqual(signals.length, 1, "one prompt is open after the pick");
		closeDialog(ui);
		await assert.rejects(grant, (e) => e.code === C.CONFIRM_CODES.USER_CANCELLED);
		assert.strictEqual(signals[0].aborted, true, "the close aborted the prompt");
		sheet.resolve(ASSERTION);
		await flush();
		assert.ok(!post.calls.some((c) => c.method === "passkeys.confirm.verify_confirmation"), "no verify after the close");
		assert.deepStrictEqual(ui.events.map((e) => e[0]), ["choose", "busy", "announce", "done"]);
		assert.deepStrictEqual(ui.events[3], ["done", false]);
		closeDialog(ui); // a second close changes nothing
		assert.strictEqual(ui.events.length, 4);
	}
});

test("closing the dialog while the verify is in flight rejects user_cancelled at once, and the action never runs", async () => {
	const late = [
		{ ok: true, status: 200, body: { message: { grant: "LATE-GRANT" } } },
		{ ok: false, status: 403, body: { exc_type: "ConfirmationFailed" } },
	];
	for (const verifyResult of late) {
		browser({ activation: false });
		const verify = deferred();
		const post = makePost({
			"myapp.api.pay": [
				{ ok: false, status: 401, body: { exc_type: "PasskeyConfirmationRequired", action: "myapp.pay", payload_fingerprint: "fp", methods: ["passkey"] } },
				{ ok: true, status: 200, body: { message: "paid" } },
			],
			"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, payload_fingerprint: "fp", methods: ["passkey"] } } }],
			"passkeys.confirm.verify_confirmation": [verify.promise],
		});
		const ui = makeWaitingUI();
		const result = promptEngine(post, ui, () => Promise.resolve(ASSERTION)).call("myapp.api.pay", { id: 1 });
		await paint();
		ui.pick("passkey");
		await flush();
		assert.ok(post.calls.some((c) => c.method === "passkeys.confirm.verify_confirmation"), "the assertion was sent");
		closeDialog(ui);
		await assert.rejects(result, (e) => e.code === C.CONFIRM_CODES.USER_CANCELLED);
		verify.resolve(verifyResult);
		await flush();
		assert.strictEqual(post.calls.filter((c) => c.method === "myapp.api.pay").length, 1, "the grant was never used");
		assert.deepStrictEqual(ui.events.map((e) => e[0]), ["choose", "busy", "announce", "done"], "nothing is shown after the close");
	}
});

test("a cancel before the pick: no prompt opens after it, and an automatic prompt that still finishes is not verified", async () => {
	for (const cancelBeforePaint of [true, false]) {
		browser();
		const post = makePost(sheetScript());
		const ui = makeWaitingUI();
		const sheet = deferred();
		let gestures = 0;
		const grant = promptEngine(post, ui, () => { gestures += 1; return sheet.promise; }).confirm("myapp.pay", { id: 1 });
		await flush();
		if (cancelBeforePaint) closeDialog(ui);
		await paint();
		if (!cancelBeforePaint) closeDialog(ui);
		await assert.rejects(grant, (e) => e.code === C.CONFIRM_CODES.USER_CANCELLED);
		assert.strictEqual(gestures, cancelBeforePaint ? 0 : 1);
		sheet.resolve(ASSERTION);
		await flush();
		assert.deepStrictEqual(ui.events.map((e) => e[0]), ["choose", "done"], "no busy state after the close");
		assert.ok(!post.calls.some((c) => c.method === "passkeys.confirm.verify_confirmation"));
	}
});

test("a password that arrives after the close is never sent", async () => {
	browser({ activation: false });
	const post = makePost(sheetScript());
	const ui = makeWaitingUI();
	const typed = deferred();
	ui.controller.collectPassword = () => typed.promise;
	const grant = promptEngine(post, ui, () => Promise.resolve(ASSERTION)).confirm("myapp.pay", { id: 1 });
	await paint();
	ui.pick("password");
	await flush();
	closeDialog(ui);
	await assert.rejects(grant, (e) => e.code === C.CONFIRM_CODES.USER_CANCELLED);
	typed.resolve("hunter2");
	await flush();
	assert.ok(!post.calls.some((c) => c.method === "passkeys.confirm.reauth_password"));
});

test("closing the dialog while a password is checked: no retry prompt after it, and no grant", async () => {
	browser({ activation: false });
	const reauth = deferred();
	const post = makePost(sheetScript({ "passkeys.confirm.reauth_password": [reauth.promise] }));
	const ui = makeWaitingUI();
	const grant = promptEngine(post, ui, () => Promise.resolve(ASSERTION)).confirm("myapp.pay", { id: 1 });
	await paint();
	ui.pick("password");
	await flush();
	closeDialog(ui);
	await assert.rejects(grant, (e) => e.code === C.CONFIRM_CODES.USER_CANCELLED);
	reauth.resolve({ ok: false, status: 401, body: {} });
	await flush();
	assert.deepStrictEqual(ui.events.map((e) => e[0]), ["choose", "password", "done"], "no password error and no second prompt");
});

test("a controller that never calls cancel works as before: a rejection cancels before the pick, and a pick confirms", async () => {
	for (const promptWithDialog of [false, true]) {
		browser({ activation: false });
		const closed = makeWaitingUI();
		const rejected = C.createConfirmEngine({ post: makePost(sheetScript()), runGesture: () => Promise.resolve(ASSERTION), ui: () => closed.controller, promptWithDialog }).confirm("myapp.pay", { id: 1 });
		await paint();
		closed.cancel();
		await assert.rejects(rejected, (e) => e.code === C.CONFIRM_CODES.USER_CANCELLED);
		assert.deepStrictEqual(closed.events.map((e) => e[0]), ["choose", "done"]);

		const picked = makeWaitingUI();
		const signals = [];
		const grant = C.createConfirmEngine({ post: makePost(sheetScript()), runGesture: (o, opts) => { signals.push(opts.signal); return Promise.resolve(ASSERTION); }, ui: () => picked.controller, promptWithDialog }).confirm("myapp.pay", { id: 1 });
		await paint();
		picked.pick("passkey");
		assert.strictEqual(await grant, "SHEET-GRANT");
		assert.strictEqual(signals[0].aborted, false);
		assert.deepStrictEqual(picked.events.map((e) => e[0]), ["choose", "busy", "announce", "done"]);
		assert.deepStrictEqual(picked.events[3], ["done", true]);
	}
});

// With only password available there is no chooseMethod: collectPassword's cancel() reports the close.
function passwordOnlyScript(reauth) {
	return {
		"myapp.api.pay": [
			{ ok: false, status: 401, body: { exc_type: "PasskeyConfirmationRequired", action: "myapp.pay", payload_fingerprint: "fp", methods: ["password"] } },
			{ ok: true, status: 200, body: { message: "paid" } },
		],
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, payload_fingerprint: "fp", methods: ["password"] } } }],
		"passkeys.confirm.reauth_password": reauth,
	};
}

test("closing a password-only confirmation while the password is checked: the action never runs, and no retry prompt opens", async () => {
	const late = [
		{ ok: true, status: 200, body: { message: { grant: "LATE-GRANT" } } },
		{ ok: false, status: 401, body: {} },
	];
	for (const reauthResult of late) {
		const reauth = deferred();
		const post = makePost(passwordOnlyScript([reauth.promise]));
		const ui = makeWaitingUI();
		const result = C.createConfirmEngine({ post, runGesture: () => Promise.reject(new Error("no gesture")), ui: () => ui.controller }).call("myapp.api.pay", { id: 1 });
		await flush();
		assert.ok(post.calls.some((c) => c.method === "passkeys.confirm.reauth_password"), "the password was sent");
		ui.events.find((e) => e[0] === "password")[1].cancel();
		await assert.rejects(result, (e) => e.code === C.CONFIRM_CODES.USER_CANCELLED);
		reauth.resolve(reauthResult);
		await flush();
		assert.strictEqual(post.calls.filter((c) => c.method === "myapp.api.pay").length, 1, "the grant was never used");
		assert.deepStrictEqual(ui.events.map((e) => e[0]), ["password", "done"], "no password error and no second prompt");
	}
});

test("a password-only controller that never calls cancel works as before: a rejection cancels, a retried password confirms", async () => {
	const closed = makeUI({ cancelPassword: true });
	const closedPost = makePost(passwordOnlyScript([]));
	await assert.rejects(C.createConfirmEngine({ post: closedPost, runGesture: () => Promise.reject(new Error()), ui: closed }).call("myapp.api.pay", { id: 1 }),
		(e) => e.code === C.CONFIRM_CODES.USER_CANCELLED);
	assert.deepStrictEqual(closed.events.map((e) => e[0]), ["password", "done"]);
	assert.ok(!closedPost.calls.some((c) => c.method === "passkeys.confirm.reauth_password"));

	const typed = makeUI({ passwords: ["wrong", "right"] });
	const post = makePost(passwordOnlyScript([
		{ ok: false, status: 401, body: {} },
		{ ok: true, status: 200, body: { message: { grant: "PW-GRANT" } } },
	]));
	assert.strictEqual(await C.createConfirmEngine({ post, runGesture: () => Promise.reject(new Error()), ui: typed }).call("myapp.api.pay", { id: 1 }), "paid");
	assert.deepStrictEqual(typed.events.map((e) => e[0]), ["password", "pwerror", "password", "done"]);
	assert.deepStrictEqual(typed.events[3], ["done", true]);
});

// ----------------------------------------------------- HTTP vs network (C11)
// A dropped fetch (transport failure) stays `network`; a REACHED server that
// returned a non-contract error (417/4xx/5xx) is `confirmation_failed` — never
// `network`. Codes stay inside the fixed taxonomy, and callers (which
// branch only on user_cancelled) keep working.

test("call(): transport failure (fetch rejects) -> network", async () => {
	const post = makePost({ "myapp.api.x": [new Error("offline")] });
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI() });
	await assert.rejects(engine.call("myapp.api.x", {}), (e) => e.code === C.CONFIRM_CODES.NETWORK);
});

test("call(): reached server returns a non-contract HTTP error -> confirmation_failed (not network)", async () => {
	const post = makePost({ "myapp.api.x": [{ ok: false, status: 500, body: { some: "error" } }] });
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI() });
	await assert.rejects(engine.call("myapp.api.x", {}), (e) => e.code === C.CONFIRM_CODES.CONFIRMATION_FAILED);
});

test("call(): 417 served-by-core on the protected method -> confirmation_failed (not network)", async () => {
	const post = makePost({ "myapp.api.x": [{ ok: false, status: 417, body: { exc_type: "PasskeyServedByCore" } }] });
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI() });
	await assert.rejects(engine.call("myapp.api.x", {}), (e) => e.code === C.CONFIRM_CODES.CONFIRMATION_FAILED);
});

// ------------------------------------------------- passkey-only switch (C2-UI)
// The toggle sends a BOOLEAN {enabled} payload through frappe.passkeys.call;
// the server 401 binds the grant to a fingerprint over {"enabled": <bool>}, the
// engine echoes that fingerprint VERBATIM into begin_confirmation, and the
// retry re-sends the SAME boolean payload with the grant header.

test("call(): set_passkey_only_login(true) echoes the {enabled:true} fingerprint + retries with grant", async () => {
	const SWITCH = "passkeys.api.credentials.set_passkey_only_login";
	const post = makePost({
		[SWITCH]: [
			{ ok: false, status: 401, body: { exc_type: "PasskeyConfirmationRequired", action: "passkeys.set_passkey_only_login", payload_fingerprint: "FP-ENABLED", methods: ["passkey"] } },
			{ ok: true, status: 200, body: { message: { passkey_only_login: 1 } } },
		],
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, payload_fingerprint: "FP-ENABLED", methods: ["passkey"] } } }],
		"passkeys.confirm.verify_confirmation": [{ ok: true, status: 200, body: { message: { grant: "PK-GRANT" } } }],
	});
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI({ method: "passkey" }) });
	const result = await engine.call(SWITCH, { enabled: true });
	assert.deepStrictEqual(result, { passkey_only_login: 1 });
	// the payload is a real boolean, not 0/1 (the fingerprint is over {"enabled": <bool>})
	const initial = post.calls.filter((c) => c.method === SWITCH)[0];
	assert.deepStrictEqual(initial.body, { enabled: true });
	assert.strictEqual(typeof initial.body.enabled, "boolean");
	// begin echoed the server fingerprint verbatim for the switch action
	const begin = post.calls.find((c) => c.method === "passkeys.confirm.begin_confirmation");
	assert.deepStrictEqual(begin.body, { action: "passkeys.set_passkey_only_login", payload_hash: "FP-ENABLED" });
	// retry re-sent the SAME boolean payload + attached the grant header
	const retry = post.calls.filter((c) => c.method === SWITCH)[1];
	assert.deepStrictEqual(retry.body, { enabled: true });
	assert.deepStrictEqual(retry.headers, { "X-Passkey-Grant": "PK-GRANT" });
});

// --------------------------------------------------- server-message surfacing (A4)
// A server refusal must not collapse into a generic string: the engine surfaces the
// message Frappe puts in `_server_messages` (e.g. the last-passkey delete guard).

function serverMsgBody(msg) {
	return { exc_type: "ValidationError", _server_messages: JSON.stringify([JSON.stringify({ message: msg })]) };
}

test("serverMessages: parses Frappe's double-encoded _server_messages, else null", () => {
	assert.strictEqual(C.serverMessages(serverMsgBody("This is your only passkey.")), "This is your only passkey.");
	assert.strictEqual(C.serverMessages({ some: "error" }), null);
	assert.strictEqual(C.serverMessages(null), null);
});

test("call(): a reached refusal with a server message surfaces it verbatim (last-passkey guard)", async () => {
	const GUARD = "This is your only passkey and passwordless login is on for your account — add another passkey (or turn off passkey-only login) before removing it.";
	const post = makePost({ "passkeys.api.credentials.delete_credential": [{ ok: false, status: 417, body: serverMsgBody(GUARD) }] });
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI() });
	await assert.rejects(
		engine.call("passkeys.api.credentials.delete_credential", { name: "x" }),
		(e) => e.code === C.CONFIRM_CODES.CONFIRMATION_FAILED && e.message === GUARD
	);
});

test("call(): retry after a confirmed grant surfaces the server message when the retry is refused", async () => {
	const GUARD = "This is your only passkey and passwordless login is on for your account.";
	const post = makePost({
		"passkeys.api.credentials.delete_credential": [
			{ ok: false, status: 401, body: { exc_type: "PasskeyConfirmationRequired", action: "passkeys.manage", payload_fingerprint: "fp", methods: ["passkey"] } },
			{ ok: false, status: 417, body: serverMsgBody(GUARD) },
		],
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, payload_fingerprint: "fp", methods: ["passkey"] } } }],
		"passkeys.confirm.verify_confirmation": [{ ok: true, status: 200, body: { message: { grant: "G" } } }],
	});
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI({ method: "passkey" }) });
	await assert.rejects(
		engine.call("passkeys.api.credentials.delete_credential", { name: "x" }),
		(e) => e.code === C.CONFIRM_CODES.CONFIRMATION_FAILED && e.message === GUARD
	);
});

// A success can carry frappe.msgprint messages too (the incomplete sign-out warning on a delete).
const SIGN_OUT_WARNING = {
	message: "The passkey no longer works, but some of a@example.com's sessions may still be signed in. Ask an administrator to clear the site cache: see <a href=\"https://example.com/recovery.html\">Someone may be using the account right now</a>.",
	indicator: "orange",
};
function successWithMessages(message, ...messages) {
	return { ok: true, status: 200, body: { message, _server_messages: JSON.stringify(messages.map((m) => JSON.stringify(m))) } };
}

test("call(): a success's server messages go to onServerMessages before it resolves; the result is unchanged", async () => {
	const post = makePost({ "passkeys.api.credentials.delete_credential": [successWithMessages({ deleted: "x" }, SIGN_OUT_WARNING)] });
	const shown = [];
	const engine = C.createConfirmEngine({
		post, runGesture: () => Promise.reject(new Error("should not run")), ui: makeUI(),
		onServerMessages: (messages) => shown.push(messages),
	});
	const result = await engine.call("passkeys.api.credentials.delete_credential", { name: "x" }).then((r) => {
		assert.strictEqual(shown.length, 1, "shown before the promise resolves");
		return r;
	});
	assert.deepStrictEqual(result, { deleted: "x" });
	assert.deepStrictEqual(shown, [[SIGN_OUT_WARNING]]);
});

test("call(): the retry after a confirmation hands its server messages over too", async () => {
	const post = makePost({
		"passkeys.api.credentials.delete_credential": [
			{ ok: false, status: 401, body: { exc_type: "PasskeyConfirmationRequired", action: "passkeys.manage", payload_fingerprint: "fp", methods: ["passkey"], _server_messages: JSON.stringify([JSON.stringify({ message: "From the 401." })]) } },
			successWithMessages({ deleted: "x" }, SIGN_OUT_WARNING, { message: "Second." }),
		],
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, payload_fingerprint: "fp", methods: ["passkey"] } } }],
		"passkeys.confirm.verify_confirmation": [{ ok: true, status: 200, body: { message: { grant: "G" } } }],
	});
	const shown = [];
	const engine = C.createConfirmEngine({
		post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI({ method: "passkey" }),
		onServerMessages: (messages) => shown.push(messages),
	});
	assert.deepStrictEqual(await engine.call("passkeys.api.credentials.delete_credential", { name: "x" }), { deleted: "x" });
	assert.deepStrictEqual(shown, [[SIGN_OUT_WARNING, { message: "Second." }]]);
});

test("call(): messages of errors the server caught are left out, and a throwing onServerMessages doesn't fail the call", async () => {
	const swallowed = { message: "Please setup default outgoing Email Account", indicator: "red", raise_exception: 1, __frappe_exc_id: "e1" };
	const shown = [];
	const engine = C.createConfirmEngine({
		post: makePost({ "myapp.a": [successWithMessages("ok", swallowed, SIGN_OUT_WARNING)], "myapp.b": [successWithMessages("ok", swallowed)] }),
		runGesture: () => Promise.reject(new Error("no")), ui: makeUI(),
		onServerMessages: (messages) => shown.push(messages),
	});
	assert.strictEqual(await engine.call("myapp.a", {}), "ok");
	assert.strictEqual(await engine.call("myapp.b", {}), "ok");
	assert.deepStrictEqual(shown, [[SIGN_OUT_WARNING]], "only the warning; nothing for a call whose only message was swallowed");
	const errors = [];
	const savedError = console.error;
	console.error = (e) => errors.push(e);
	try {
		const throwing = C.createConfirmEngine({
			post: makePost({ "myapp.c": [successWithMessages("ok", SIGN_OUT_WARNING)] }),
			runGesture: () => Promise.reject(new Error("no")), ui: makeUI(),
			onServerMessages: () => { throw new Error("display broke"); },
		});
		assert.strictEqual(await throwing.call("myapp.c", {}), "ok");
	} finally {
		console.error = savedError;
	}
	assert.strictEqual(errors.length, 1);
});

test("call(): no onServerMessages, no messages, or a refusal: nothing is handed over", async () => {
	const shown = [];
	const onServerMessages = (messages) => shown.push(messages);
	const quiet = C.createConfirmEngine({ post: makePost({ "myapp.ping": [{ ok: true, status: 200, body: { message: 1 } }] }), runGesture: () => Promise.reject(new Error("no")), ui: makeUI(), onServerMessages });
	assert.strictEqual(await quiet.call("myapp.ping", {}), 1);
	const refused = C.createConfirmEngine({ post: makePost({ "myapp.x": [{ ok: false, status: 417, body: serverMsgBody("No.") }] }), runGesture: () => Promise.reject(new Error("no")), ui: makeUI(), onServerMessages });
	await assert.rejects(refused.call("myapp.x", {}), (e) => e.message === "No.");
	assert.deepStrictEqual(shown, []);
	const headless = C.createConfirmEngine({ post: makePost({ "myapp.y": [successWithMessages("ok", SIGN_OUT_WARNING)] }), runGesture: () => Promise.reject(new Error("no")), ui: makeUI() });
	assert.strictEqual(await headless.call("myapp.y", {}), "ok");
});

for (const [excType, message] of [
	["CeremonyExpired", "That took too long — please try again."],
	["CeremonyFailed", "That passkey didn't confirm it's you. Try again, or use your password."],
]) {
	test(`confirmation verify ${excType} without server messages shows the right copy`, async () => {
		const post = makePost({
			"passkeys.confirm.begin_confirmation": [{ ok: true, body: { message: { state_id: "s", options: REQ_OPTIONS, methods: ["passkey"] } } }],
			"passkeys.confirm.verify_confirmation": [{ ok: false, status: 401, body: { exc_type: excType } }],
		});
		const engine = C.createConfirmEngine({ post, runGesture: () => Promise.resolve(ASSERTION), ui: makeUI() });
		await assert.rejects(engine.confirm("myapp.pay", {}),
			(e) => e.code === C.CONFIRM_CODES.CONFIRMATION_FAILED && e.message === message);
		assert.strictEqual(post.calls.length, 2, "never replay an assertion");
	});
}
