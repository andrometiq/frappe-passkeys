// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Conditional-UI (autofill) passwordless login. A discoverable UV
// credential is seeded through the committed
// registration ceremony (virtual authenticator generates the ES256 key); the
// login page patches #login_email to `autocomplete="username webauthn"` and arms
// a native `mediation:"conditional"` get(). Cypress cannot deterministically
// choose an autofill credential in headless Chromium, so completion is tested by
// fulfilling the same discoverable assertion path after separately proving the
// app asked the browser for conditional mediation.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

function install_pending_get(win, collector) {
	const creds = win.navigator && win.navigator.credentials;
	if (!creds || !creds.get) return;
	Object.defineProperty(creds, "get", {
		configurable: true,
		value(options) {
			if (collector) collector.push(options);
			return new Promise((resolve, reject) => {
				if (options && options.signal) {
					options.signal.addEventListener(
						"abort",
						() => reject(new win.DOMException("aborted", "AbortError")),
						{ once: true }
					);
				}
			});
		},
	});
}

function record_native_get(win, collector) {
	const creds = win.navigator && win.navigator.credentials;
	const nativeGet = creds && creds.get && creds.get.bind(creds);
	if (!nativeGet) return;
	Object.defineProperty(creds, "get", {
		configurable: true,
		value(options) {
			if (collector) collector.push(options);
			const promise = nativeGet(options);
			win.__passkey_native_get_state = "started";
			promise
				.then(() => {
					win.__passkey_native_get_state = "resolved";
				})
				.catch((err) => {
					win.__passkey_native_get_state = err && err.name ? err.name : "rejected";
				});
			return promise;
		},
	});
}

function abort_conditional_get() {
	return cy.window().then((win) => {
		const abort = win.frappe && win.frappe._passkey_login && win.frappe._passkey_login._state.conditionalAbort;
		if (abort) abort.abort();
	});
}

chromium_only("passkey conditional-UI login", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
		// The shared CI runner IP fills the guest ceremony rate limits (begin_login
		// 30/60s, verify_login 10/60s) across earlier specs. Reset them (while still
		// authed) so this spec's login ceremonies start with a fresh budget instead
		// of 429ing.
		cy.call("passkeys.tests.ui_test_helpers.clear_guest_ceremony_rate_limit");
	});

	after(() => {
		cy.login(USER, PW());
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("patches the username field for webauthn autofill", () => {
		cy.visit_login({
			onBeforeLoad(win) {
				install_pending_get(win);
			},
		});
		cy.get("#login_email").should("have.attr", "autocomplete").and("contain", "webauthn");
		abort_conditional_get();
	});

	it("arms native conditional mediation without immediate browser rejection", () => {
		cy.intercept("POST", "**/passkeys.passkey.begin_login").as("begin_login");
		cy.intercept_frappe_method("passkeys.passkey.verify_login", "verify_login");
		cy.stub_post_login_shell();
		cy.hold_passkey_taps();
		cy.visit_login({
			onBeforeLoad(win) {
				win.__passkey_get_calls = [];
				record_native_get(win, win.__passkey_get_calls);
			},
		});
		cy.wait("@begin_login").its("response.statusCode").should("be.within", 200, 299);
		cy.get("#login_email").should("have.attr", "autocomplete").and("contain", "webauthn");
		cy.window().should((win) => {
			const calls = win.__passkey_get_calls || [];
			const call = calls.find((entry) => entry && entry.mediation === "conditional");
			expect(call, "conditional get call").to.exist;
			expect(call.publicKey, "publicKey options").to.exist;
			expect(call.publicKey.allowCredentials || [], "discoverable credential request").to.have.length(0);
			expect(call.signal, "abort signal").to.exist;
			expect(call.signal.aborted, "conditional request remains pending").to.eq(false);
			expect(win.frappe._passkey_login._state.conditionalAbort).to.exist;
			expect(win.__passkey_native_get_state, "native get state").to.be.oneOf(["started", "resolved"]);
		});
		cy.get("#passkey-login-btn").should("be.visible");
		abort_conditional_get();
		cy.simulate_passkey_tap();
	});

	it("routes a fulfilled discoverable credential assertion into a passwordless session", () => {
		cy.simulate_passkey_tap();
		cy.intercept_frappe_method("passkeys.passkey.verify_login", "verify_login");
		cy.stub_post_login_shell();
		cy.visit_login({
			onBeforeLoad(win) {
				const creds = win.navigator && win.navigator.credentials;
				const nativeGet = creds && creds.get && creds.get.bind(creds);
				win.__passkey_get_calls = [];
				if (!nativeGet) return;
				Object.defineProperty(creds, "get", {
					configurable: true,
					value(options) {
						win.__passkey_get_calls.push(options);
						if (options && options.mediation === "conditional") {
							// Native conditional autofill selection is intentionally split
							// from this completion assertion; the test above proves
							// mediation, while this proves the fulfilled assertion path.
							return nativeGet({ publicKey: options.publicKey, signal: options.signal });
						}
						return nativeGet(options);
					},
				});
			},
		});
		cy.window().should((win) => {
			const call = (win.__passkey_get_calls || []).find((entry) => entry && entry.mediation === "conditional");
			expect(call, "conditional get call").to.exist;
			expect(call.publicKey, "publicKey options").to.exist;
		});
		cy.wait("@verify_login", { timeout: 20000 }).its("response.statusCode").should("be.within", 200, 299);
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/(app|desk)/);
		cy.assert_logged_user(USER);
	});
});
