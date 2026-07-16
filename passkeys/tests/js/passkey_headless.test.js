// passkey_headless.test.js — dependency-free unit harness for the PURE
// createHeadless ceremony orchestrator (passkey_headless.bundle.js). Runs WITHOUT the
// bench and WITHOUT jsdom:  node --test passkeys/tests/js
//
// Covers the whole headless lifecycle a custom UI drives: first-factor login
// (begin -> gesture -> verify, disabled, gesture-cancel mapping, typed-401
// mapping, uv-setup surfacing, transport failure), registration (happy path +
// label, the sudo dance, already-registered / cancel / expired mapping, the
// no-confirm-engine reject), and list / rename / remove / setPasswordlessOnly
// delegation. The real passkey_common is injected as `common` so the taxonomy
// mapping is exercised for real; browser deps (post / gesture / confirm / call)
// are scripted doubles.

const test = require("node:test");
const assert = require("node:assert");
const C = require("../../public/js/passkey_common.bundle.js");
const M = require("../../public/js/passkey_manage_common.bundle.js");
const H = require("../../public/js/passkey_headless.bundle.js");

const LM = H.LOGIN_METHODS;
const MM = M.MANAGE_METHODS;

// ------------------------------------------------------------- test doubles
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

const REQ_OPTIONS = { challenge: "abc", rpId: "example.com", userVerification: "required", allowCredentials: [] };
const CREATE_OPTIONS = { challenge: "abc", rp: { id: "example.com" }, user: { id: "dXNlcg", name: "u" } };
const ASSERTION = { id: "cred1", type: "public-key", response: { userHandle: "aGFuZGxl" } };
const ATTESTATION = { id: "new1", type: "public-key", response: {} };

function base(overrides) {
	return Object.assign(
		{
			common: C,
			capabilities: () => Promise.resolve({ supported: true }),
			getConfirm: () => null,
			getCall: () => null,
			manageMethods: MM,
			manageAction: M.MANAGE_ACTION,
			loginMethods: LM,
		},
		overrides
	);
}

// ------------------------------------------------------------- login tests

test("login(): begin (first-factor) -> gesture -> verify -> {ok, redirect}", async () => {
	const post = makePost({
		[LM.begin_login]: [{ ok: true, status: 200, body: { message: { enabled: true, modes: { first_factor: true }, state_id: "s1", options: REQ_OPTIONS } } }],
		[LM.verify_login]: [{ ok: true, status: 200, body: { home_page: "/app" } }],
	});
	let gestureOpts = null;
	const h = H.createHeadless(base({ post, getAssertion: (o) => { gestureOpts = o; return Promise.resolve(ASSERTION); } }));
	const r = await h.login();
	assert.deepStrictEqual(r, { ok: true, redirect: "/app", raw: { home_page: "/app" } });
	assert.strictEqual(gestureOpts, REQ_OPTIONS);
	// verify_login posted the assertion serialized as a string + the state id
	assert.deepStrictEqual(post.calls[1], { method: LM.verify_login, body: { state_id: "s1", credential: JSON.stringify(ASSERTION) }, headers: {} });
});

test("login(): mode off -> {ok:false, reason:'disabled'} (no gesture)", async () => {
	const post = makePost({ [LM.begin_login]: [{ ok: true, status: 200, body: { message: { enabled: false, modes: { first_factor: false } } } }] });
	let gestured = false;
	const h = H.createHeadless(base({ post, getAssertion: () => { gestured = true; return Promise.resolve(ASSERTION); } }));
	const r = await h.login();
	assert.deepStrictEqual(r, { ok: false, reason: "disabled", statusState: "idle" });
	assert.strictEqual(gestured, false, "no gesture when the mode is off");
});

test("login(): second-factor-only site never runs the first-factor gesture", async () => {
	const post = makePost({ [LM.begin_login]: [{ ok: true, status: 200, body: { message: { enabled: true, modes: { first_factor: false, second_factor: true } } } }] });
	const h = H.createHeadless(base({ post, getAssertion: () => Promise.reject(new Error("should not run")) }));
	const r = await h.login();
	assert.strictEqual(r.reason, "disabled");
});

test("login(): a cancelled gesture maps through the DOM taxonomy -> cancelled", async () => {
	const post = makePost({ [LM.begin_login]: [{ ok: true, status: 200, body: { message: { enabled: true, modes: { first_factor: true }, state_id: "s", options: REQ_OPTIONS } } }] });
	const cancel = new Error("x"); cancel.name = "NotAllowedError";
	const h = H.createHeadless(base({ post, getAssertion: () => Promise.reject(cancel) }));
	const r = await h.login();
	assert.strictEqual(r.ok, false);
	assert.strictEqual(r.reason, "gesture");
	assert.strictEqual(r.code, "user_cancelled");
	assert.strictEqual(r.statusState, "cancelled"); // reuses the shipped LOGIN_STATES copy
	// verify_login was never called (an assertion is never invented)
	assert.strictEqual(post.calls.filter((c) => c.method === LM.verify_login).length, 0);
});

test("verifyLogin(): a typed UnknownCredential 401 -> removed state (A5), never throws", async () => {
	const post = makePost({ [LM.verify_login]: [{ ok: false, status: 401, body: { exc_type: "UnknownCredential" } }] });
	const h = H.createHeadless(base({ post, getAssertion: () => Promise.resolve(ASSERTION) }));
	const r = await h.verifyLogin("s", ASSERTION);
	assert.deepStrictEqual(r, { ok: false, reason: "server", kind: "unknown_credential", status: 401, message: null, statusState: "removed" });
});

test("verifyLogin(): UVSetupRequired surfaces the top-level setup_id", async () => {
	const post = makePost({ [LM.verify_login]: [{ ok: false, status: 401, body: { exc_type: "UVSetupRequired", setup_id: "uvs-1" } }] });
	const h = H.createHeadless(base({ post, getAssertion: () => Promise.resolve(ASSERTION) }));
	const r = await h.verifyLogin("s", ASSERTION);
	assert.strictEqual(r.kind, "uv_setup_required");
	assert.strictEqual(r.setupId, "uvs-1");
});

test("verifyLogin(): a transport failure resolves reason:'network' (never rejects)", async () => {
	const post = makePost({ [LM.verify_login]: [new Error("offline")] });
	const h = H.createHeadless(base({ post, getAssertion: () => Promise.resolve(ASSERTION) }));
	const r = await h.verifyLogin("s", ASSERTION);
	assert.deepStrictEqual(r, { ok: false, reason: "network", kind: "network", status: 0, message: null, statusState: "failed" });
});

test("completeUvSetup(): posts the setup id/password and resolves the login result", async () => {
	const post = makePost({
		[LM.complete_uv_setup]: [{ ok: true, status: 200, body: { home_page: "/app" } }],
	});
	const h = H.createHeadless(base({ post }));
	assert.deepStrictEqual(await h.completeUvSetup("uvs-1", "secret"), {
		ok: true, redirect: "/app", raw: { home_page: "/app" },
	});
	assert.deepStrictEqual(post.calls[0], {
		method: LM.complete_uv_setup, body: { setup_id: "uvs-1", pwd: "secret" }, headers: {},
	});
});

test("completeUvSetup(): server and transport failures stay structured", async () => {
	const refused = H.createHeadless(base({
		post: makePost({ [LM.complete_uv_setup]: [{ ok: false, status: 401, body: { exc_type: "CeremonyExpired" } }] }),
	}));
	const serverResult = await refused.completeUvSetup("expired", "secret");
	assert.strictEqual(serverResult.ok, false);
	assert.strictEqual(serverResult.kind, "ceremony_expired");
	assert.strictEqual(serverResult.reason, "server");

	const offline = H.createHeadless(base({
		post: makePost({ [LM.complete_uv_setup]: [new Error("offline")] }),
	}));
	assert.strictEqual((await offline.completeUvSetup("uvs-1", "secret")).reason, "network");
});

// ------------------------------------------------------- registration tests

test("register(): begin -> create -> verify -> data; wire calls exact", async () => {
	const post = makePost({
		[MM.beginRegistration]: [{ ok: true, status: 200, body: { message: { state_id: "r1", options: CREATE_OPTIONS } } }],
		[MM.verifyRegistration]: [{ ok: true, status: 200, body: { message: { name: "WC-1", label: "Apple Passwords", signal: {} } } }],
	});
	let createOpts = null;
	const h = H.createHeadless(base({ post, createCredential: (o) => { createOpts = o; return Promise.resolve(ATTESTATION); } }));
	const data = await h.register();
	assert.deepStrictEqual(data, { name: "WC-1", label: "Apple Passwords", signal: {} });
	assert.deepStrictEqual(post.calls[0], { method: MM.beginRegistration, body: { flow: "explicit" }, headers: {} });
	assert.strictEqual(createOpts, CREATE_OPTIONS);
	// verify posted the stringified attestation + state id, and NO label (none passed)
	assert.deepStrictEqual(post.calls[1], { method: MM.verifyRegistration, body: { state_id: "r1", credential: JSON.stringify(ATTESTATION) }, headers: {} });
});

test("register(): signals authoritative credential state after successful verification", async () => {
	const signal = { rp_id: "example.com", user_handle: "h", credential_ids: ["new1"] };
	const seen = [];
	const post = makePost({
		[MM.beginRegistration]: [{ ok: true, status: 200, body: { message: { state_id: "r1", options: CREATE_OPTIONS } } }],
		[MM.verifyRegistration]: [{ ok: true, status: 200, body: { message: { name: "WC-1", signal } } }],
	});
	const h = H.createHeadless(base({
		post,
		createCredential: () => Promise.resolve(ATTESTATION),
		signalCredentialState: (data) => seen.push(data),
	}));
	await h.register();
	assert.deepStrictEqual(seen, [{ name: "WC-1", signal }]);
});

test("register({label}): forwards the label to verify_registration", async () => {
	const post = makePost({
		[MM.beginRegistration]: [{ ok: true, status: 200, body: { message: { state_id: "r1", options: CREATE_OPTIONS } } }],
		[MM.verifyRegistration]: [{ ok: true, status: 200, body: { message: { name: "WC-2", label: "Work key" } } }],
	});
	const h = H.createHeadless(base({ post, createCredential: () => Promise.resolve(ATTESTATION) }));
	await h.register({ label: "Work key" });
	assert.strictEqual(post.calls.find((c) => c.method === MM.verifyRegistration).body.label, "Work key");
});

test("register(): sudo dance — begin 401 -> confirm(passkeys.manage) -> retry begin -> create -> verify", async () => {
	const post = makePost({
		[MM.beginRegistration]: [
			{ ok: false, status: 401, body: { exc_type: "PasskeyConfirmationRequired", action: "passkeys.manage", methods: ["passkey", "password"] } },
			{ ok: true, status: 200, body: { message: { state_id: "r9", options: CREATE_OPTIONS } } },
		],
		[MM.verifyRegistration]: [{ ok: true, status: 200, body: { message: { name: "WC-9" } } }],
	});
	const confirmCalls = [];
	const h = H.createHeadless(base({
		post,
		createCredential: () => Promise.resolve(ATTESTATION),
		getConfirm: () => (action) => { confirmCalls.push(action); return Promise.resolve("GRANT"); },
	}));
	const data = await h.register();
	assert.strictEqual(data.name, "WC-9");
	assert.deepStrictEqual(confirmCalls, ["passkeys.manage"]);
	assert.strictEqual(post.calls.filter((c) => c.method === MM.beginRegistration).length, 2, "begin retried exactly once after confirm");
});

test("register(): begin 401 but no confirm engine -> confirmation_unavailable", async () => {
	const post = makePost({ [MM.beginRegistration]: [{ ok: false, status: 401, body: { exc_type: "PasskeyConfirmationRequired", action: "passkeys.manage", methods: ["passkey"] } }] });
	const h = H.createHeadless(base({ post, createCredential: () => Promise.resolve(ATTESTATION), getConfirm: () => null }));
	await assert.rejects(h.register(), (e) => e.code === "confirmation_unavailable");
});

test("register(): create InvalidStateError -> already_registered", async () => {
	const post = makePost({ [MM.beginRegistration]: [{ ok: true, status: 200, body: { message: { state_id: "r", options: CREATE_OPTIONS } } }] });
	const dup = new Error("dup"); dup.name = "InvalidStateError";
	const h = H.createHeadless(base({ post, createCredential: () => Promise.reject(dup) }));
	await assert.rejects(h.register(), (e) => e.code === "already_registered");
});

test("register(): create NotAllowedError -> user_cancelled", async () => {
	const post = makePost({ [MM.beginRegistration]: [{ ok: true, status: 200, body: { message: { state_id: "r", options: CREATE_OPTIONS } } }] });
	const cancel = new Error("x"); cancel.name = "NotAllowedError";
	const h = H.createHeadless(base({ post, createCredential: () => Promise.reject(cancel) }));
	await assert.rejects(h.register(), (e) => e.code === "user_cancelled");
});

test("register(): verify ceremony_expired -> add_expired", async () => {
	const post = makePost({
		[MM.beginRegistration]: [{ ok: true, status: 200, body: { message: { state_id: "r", options: CREATE_OPTIONS } } }],
		[MM.verifyRegistration]: [{ ok: false, status: 401, body: { exc_type: "CeremonyExpired" } }],
	});
	const h = H.createHeadless(base({ post, createCredential: () => Promise.resolve(ATTESTATION) }));
	await assert.rejects(h.register(), (e) => e.code === "add_expired");
});

// ------------------------------------------------------- management tests

test("listCredentials(): unwraps the server payload", async () => {
	const post = makePost({ [MM.list]: [{ ok: true, status: 200, body: { message: { credentials: [{ name: "a" }], passkey_only_login: 1 } } }] });
	const h = H.createHeadless(base({ post }));
	assert.deepStrictEqual(await h.listCredentials(), { credentials: [{ name: "a" }], passkey_only_login: 1 });
});

test("listCredentials(): a failed read rejects list_failed", async () => {
	const post = makePost({ [MM.list]: [{ ok: false, status: 500, body: null }] });
	const h = H.createHeadless(base({ post }));
	await assert.rejects(h.listCredentials(), (e) => e.code === "list_failed");
});

test("renameCredential(): posts name+label, returns the row", async () => {
	const post = makePost({ [MM.rename]: [{ ok: true, status: 200, body: { message: { name: "a", label: "New" } } }] });
	const h = H.createHeadless(base({ post }));
	assert.deepStrictEqual(await h.renameCredential("a", "New"), { name: "a", label: "New" });
	assert.deepStrictEqual(post.calls[0].body, { name: "a", label: "New" });
});

test("removeCredential(): routes through frappe.passkeys.call (sudo-gated)", async () => {
	const callArgs = [];
	const h = H.createHeadless(base({ post: makePost({}), getCall: () => (m, a) => { callArgs.push([m, a]); return Promise.resolve({ deleted: a.name }); } }));
	const r = await h.removeCredential("WC-1");
	assert.deepStrictEqual(r, { deleted: "WC-1" });
	assert.deepStrictEqual(callArgs, [[MM.del, { name: "WC-1" }]]);
});

test("removeCredential(): refreshes and signals authoritative state after deletion", async () => {
	const signal = { rp_id: "example.com", user_handle: "h", credential_ids: [] };
	const seen = [];
	const post = makePost({ [MM.getSignalData]: [{ ok: true, status: 200, body: { message: signal } }] });
	const h = H.createHeadless(base({
		post,
		getCall: () => () => Promise.resolve({ deleted: "WC-1" }),
		signalCredentialState: (data) => seen.push(data),
	}));
	assert.deepStrictEqual(await h.removeCredential("WC-1"), { deleted: "WC-1" });
	assert.deepStrictEqual(seen, [signal]);
});

test("removeCredential(): no confirm engine -> confirmation_unavailable", async () => {
	const h = H.createHeadless(base({ post: makePost({}), getCall: () => null }));
	await assert.rejects(h.removeCredential("WC-1"), (e) => e.code === "confirmation_unavailable");
});

test("setPasswordlessOnly(): routes a BOOLEAN {enabled} through call", async () => {
	const callArgs = [];
	const h = H.createHeadless(base({ post: makePost({}), getCall: () => (m, a) => { callArgs.push([m, a]); return Promise.resolve({ passkey_only_login: 1 }); } }));
	await h.setPasswordlessOnly(1);
	assert.deepStrictEqual(callArgs, [[MM.setPasskeyOnly, { enabled: true }]]);
	assert.strictEqual(typeof callArgs[0][1].enabled, "boolean");
});

test("detectCapabilities(): passes through the injected probe", async () => {
	const h = H.createHeadless(base({ post: makePost({}), capabilities: () => Promise.resolve({ supported: true, uvpaa: false }) }));
	assert.deepStrictEqual(await h.detectCapabilities(), { supported: true, uvpaa: false });
});
