// passkey_login_translations.test.js — the app catalog loader (passkey_common) the
// login and portal bundles await before their first translated paint.

const test = require("node:test");
const assert = require("node:assert");

const C = require("../../public/js/passkey_common.bundle.js");

global.window = {
	frappe: {
		_messages: { "Core label": "Libellé principal" },
		_translations_loaded: Promise.resolve(),
	},
};

test("translation loader bypasses caches and merges the returned app catalog", async () => {
	let request;
	global.fetch = (url, options) => {
		request = { url, options };
		return Promise.resolve({
			ok: true,
			json: () => Promise.resolve({ message: { "Sign in with a passkey": "Connexion avec une clé" } }),
		});
	};
	await C.loadAppTranslations();

	assert.strictEqual(request.url, "/api/method/passkeys.passkey.get_app_translations");
	assert.strictEqual(request.options.method, "GET");
	assert.strictEqual(request.options.cache, "no-store");
	assert.strictEqual(window.frappe._messages["Core label"], "Libellé principal");
	assert.strictEqual(window.frappe._messages["Sign in with a passkey"], "Connexion avec une clé");
});

test("translation loader resolves (English fallback) when the catalog request fails", async () => {
	global.fetch = () => Promise.reject(new Error("offline"));
	await C.loadAppTranslations();
	global.fetch = () => Promise.resolve({ ok: false, json: () => Promise.reject(new Error("not json")) });
	await C.loadAppTranslations();
});

test("translation loader skips the request on an English page", async () => {
	let called = false;
	global.fetch = () => { called = true; return Promise.resolve({ ok: true, json: () => Promise.resolve({}) }); };
	global.document = { documentElement: { lang: "en" } };
	try {
		await C.loadAppTranslations();
	} finally {
		delete global.document;
	}
	assert.strictEqual(called, false);
});
