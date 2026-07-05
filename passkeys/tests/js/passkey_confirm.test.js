// passkey_confirm.test.js — dependency-free unit harness for the PURE §7
// action-confirmation logic in passkey_common.js::createConfirmEngine + helpers.
// Runs WITHOUT the bench and WITHOUT jsdom:  node --test passkeys/tests/js
//
// Covers: 401 contract parsing (exc_type match only), grant-header build,
// signature dedupe, capability parsing, grant extraction (message-wrapped),
// the full begin->gesture->verify->grant happy path, the frappe.passkeys.call
// 401 retry + VERBATIM payload_fingerprint echo (A36) + grant-header attach,
// params/payload_hash mutual exclusion, password-fallback leg, fallback_unavailable,
// user-cancel mapping, DOMException mapping through the gesture, single-retry cap,
// and concurrent-invocation dialog sharing (A44).

const test = require("node:test");
const assert = require("node:assert");
const C = require("../../public/js/passkey_common.js");

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
	return function () {
		return {
			chooseMethod(info) {
				events.push(["choose", info]);
				if (opts.cancel) return Promise.reject(new C.ConfirmError(C.CONFIRM_CODES.USER_CANCELLED, "x"));
				return Promise.resolve(opts.method || "passkey");
			},
			collectPassword() {
				events.push(["password"]);
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
	};
}

const REQ_OPTIONS = { challenge: "abc", rpId: "example.com", userVerification: "required", allowCredentials: [] };
const ASSERTION = { id: "cred1", type: "public-key", response: {} };

// -------------------------------------------------------- helper unit tests

test("parseConfirmationRequired matches exc_type ONLY", () => {
	const body = { exc_type: "PasskeyConfirmationRequired", action: "a.b", payload_fingerprint: "ff", methods: ["passkey", "password"] };
	const got = C.parseConfirmationRequired(body);
	assert.deepStrictEqual(got, { action: "a.b", payloadFingerprint: "ff", methods: ["passkey", "password"] });
	assert.strictEqual(C.parseConfirmationRequired({ exc_type: "SomethingElse" }), null);
	assert.strictEqual(C.parseConfirmationRequired({ action: "a.b" }), null); // no exc_type
	assert.strictEqual(C.parseConfirmationRequired(null), null);
});

test("buildGrantHeaders uses the pinned header name (mirrors session.py)", () => {
	assert.deepStrictEqual(C.buildGrantHeaders("tok"), { "X-Passkey-Grant": "tok" });
	assert.deepStrictEqual(C.buildGrantHeaders(""), {}); // no empty token
	assert.strictEqual(C.GRANT_HEADER, "X-Passkey-Grant");
	assert.strictEqual(C.GRANT_KWARG, "_passkey_grant");
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
	// begin got RAW params, never a hash (A36)
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
	// begin echoed the fingerprint verbatim as payload_hash, and sent NO params (A36 mutual exclusion)
	const beginCall = post.calls.find((c) => c.method === "passkeys.confirm.begin_confirmation");
	assert.deepStrictEqual(beginCall.body, { action: "myapp.release_payment", payload_hash: "SERVER-FP" });
	assert.ok(!("params" in beginCall.body));
	// the retry attached the grant header
	const retry = post.calls.filter((c) => c.method === "myapp.api.release_payment")[1];
	assert.deepStrictEqual(retry.headers, { "X-Passkey-Grant": "GRANT-2" });
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
		"passkeys.confirm.begin_confirmation": [{ ok: true, status: 200, body: { message: { state_id: "s", options: REQ_OPTIONS, payload_fingerprint: "fp9", methods: ["password"] } } }],
		"passkeys.confirm.reauth_password": [{ ok: true, status: 200, body: { message: { grant: "PW-GRANT" } } }],
	});
	const engine = C.createConfirmEngine({ post, runGesture: () => Promise.reject(new Error("no gesture")), ui: makeUI({ method: "password", password: "s3cret" }) });
	const grant = await engine.confirm("myapp.pay", { id: 1 });
	assert.strictEqual(grant, "PW-GRANT");
	const rc = post.calls.find((c) => c.method === "passkeys.confirm.reauth_password");
	// reauth carries action + fingerprint so the server can mint an ACTION grant (not a bare sudo seed)
	assert.deepStrictEqual(rc.body, { pwd: "s3cret", action: "myapp.pay", payload_fingerprint: "fp9" });
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
