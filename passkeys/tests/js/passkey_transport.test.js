// The shared browser transport and gestures in passkey_common (C.post, C.getAssertion,
// C.createCredential) that every bundle uses. Runs in its own process, so the window /
// navigator / fetch globals set here never reach the pure suites.
//
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");
const C = require("../../public/js/passkey_common.bundle.js");

function installNavigator(value) {
	Object.defineProperty(globalThis, "navigator", { configurable: true, enumerable: true, value, writable: true });
}

function captureFetch(response) {
	const calls = [];
	global.fetch = (url, options) => {
		calls.push({ url, options });
		return Promise.resolve(response);
	};
	return calls;
}

test("post: same-origin JSON POST that resolves {ok, status, body} for any status", async () => {
	global.window = { frappe: { csrf_token: "tok" } };
	const calls = captureFetch({ ok: false, status: 401, json: () => Promise.resolve({ exc_type: "X" }) });
	const res = await C.post("app.method", { a: 1 }, { "X-Passkey-Grant": "g" });
	assert.deepStrictEqual(res, { ok: false, status: 401, body: { exc_type: "X" } });
	assert.strictEqual(calls[0].url, "/api/method/app.method");
	assert.strictEqual(calls[0].options.method, "POST");
	assert.strictEqual(calls[0].options.credentials, "same-origin");
	assert.strictEqual(calls[0].options.body, JSON.stringify({ a: 1 }));
	assert.strictEqual(calls[0].options.headers["X-Frappe-CSRF-Token"], "tok");
	assert.strictEqual(calls[0].options.headers["X-Passkey-Grant"], "g", "extra headers are merged");

	captureFetch({ ok: true, status: 200, json: () => Promise.reject(new Error("not json")) });
	assert.deepStrictEqual(await C.post("m"), { ok: true, status: 200, body: null }, "a non-JSON body is null");
});

test("post: CSRF token from csrf_token, boot or session; a guest's \"None\" is never sent", async () => {
	for (const [frappe, expected] of [
		[{ boot: { csrf_token: "boot-tok" } }, "boot-tok"],
		[{ session: { csrf_token: "session-tok" } }, "session-tok"],
		[{ csrf_token: "None" }, undefined],
		[{}, undefined],
	]) {
		global.window = { frappe };
		const calls = captureFetch({ ok: true, status: 200, json: () => Promise.resolve({}) });
		await C.post("m", {});
		assert.strictEqual(calls[0].options.headers["X-Frappe-CSRF-Token"], expected);
	}
});

test("post: a transport failure rejects", async () => {
	global.fetch = () => Promise.reject(new Error("offline"));
	await assert.rejects(C.post("m", {}), /offline/);
});

test("createCredential: injects credProps, passes mediation/signal and serializes", async () => {
	global.window = {}; // no native parseCreationOptionsFromJSON: the polyfill decodes
	let request = null;
	installNavigator({ credentials: { create: (r) => { request = r; return Promise.resolve({ toJSON: () => ({ id: "new" }) }); } } });
	const signal = {};
	const json = await C.createCredential(
		{ challenge: "AQI", user: { id: "Aw", name: "u" }, extensions: { x: 1 } },
		{ mediation: "conditional", signal },
	);
	assert.deepStrictEqual(json, { id: "new" });
	assert.deepStrictEqual(Array.from(request.publicKey.challenge), [1, 2]);
	assert.deepStrictEqual(Array.from(request.publicKey.user.id), [3]);
	assert.deepStrictEqual(request.publicKey.extensions, { x: 1, credProps: true });
	assert.strictEqual(request.mediation, "conditional");
	assert.strictEqual(request.signal, signal);
});

test("gestures reject NotSupportedError without WebAuthn and NotAllowedError on a null credential", async () => {
	installNavigator({});
	await assert.rejects(C.getAssertion({ challenge: "AQI" }), (e) => e.name === "NotSupportedError");
	await assert.rejects(C.createCredential({ challenge: "AQI" }), (e) => e.name === "NotSupportedError");
	installNavigator({ credentials: { get: () => Promise.resolve(null), create: () => Promise.resolve(null) } });
	await assert.rejects(C.getAssertion({ challenge: "AQI" }), (e) => e.name === "NotAllowedError");
	await assert.rejects(C.createCredential({ challenge: "AQI" }), (e) => e.name === "NotAllowedError");
});

test("getAssertion: an options parse failure rejects instead of throwing", async () => {
	window.PublicKeyCredential = { parseRequestOptionsFromJSON: () => { throw new Error("bad options"); } };
	installNavigator({ credentials: { get: () => Promise.resolve({}) } });
	const pending = C.getAssertion({});
	assert.ok(pending instanceof Promise);
	await assert.rejects(pending, /bad options/);
	delete window.PublicKeyCredential;
});

test("escapeHtml escapes markup and quotes; null is empty", () => {
	assert.strictEqual(C.escapeHtml(`<a href="x">'&'</a>`), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;");
	assert.strictEqual(C.escapeHtml(null), "");
});
