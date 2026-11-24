// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// "Sign in with a passkey" with WebAuthn immediate UI mode (Chrome 149+). The click asks
// for this device's passkeys first; when there are none the browser says so at once and the
// full sheet opens in the same click, on the same ceremony. Conditional UI is armed but held
// pending here (with a credential, the virtual authenticator can answer the autofill request by
// itself), so the click must abort it before its own request. The CDP virtual authenticator
// answers without Chrome's picker, so closing the picker (no second sheet) is pinned by
// passkeys/tests/js/passkey_login_immediate.test.js.

const has_immediate_ui =
	Cypress.isBrowser({ family: "chromium" }) &&
	Cypress.browser.name !== "electron" &&
	Cypress.browser.majorVersion >= 149;
const immediate_only = has_immediate_ui ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

// Every get() the login page makes, kept in the spec so it survives the post-login redirect.
// The autofill request stays pending until aborted; the browser answers every other one.
const gets = [];
const record_gets = (win) => {
	const credentials = win.navigator && win.navigator.credentials;
	const real_get = credentials.get.bind(credentials);
	gets.length = 0;
	Object.defineProperty(credentials, "get", {
		configurable: true,
		value(options) {
			gets.push({
				ui_mode: options.uiMode,
				mediation: options.mediation,
				challenge: Array.from(new Uint8Array(options.publicKey.challenge)).join(","),
				is_aborted: () => !!(options.signal && options.signal.aborted),
			});
			if (options.mediation !== "conditional") return real_get(options);
			return new Promise((resolve, reject) => {
				options.signal.addEventListener("abort", () => reject(new win.DOMException("aborted", "AbortError")), {
					once: true,
				});
			});
		},
	});
};

const button_gets = () => gets.filter((get) => get.mediation !== "conditional");

// Immediate mode needs a real user activation, which Cypress's synthetic click doesn't give, so
// the button is clicked through the browser's input pipeline (cy.real_click).

immediate_only("passkey sign-in with immediate UI mode", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.clear_guest_ceremony_rate_limit();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
	});

	after(() => {
		cy.login(USER, PW());
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	const visit_with_conditional_armed = () => {
		cy.visit_login({ onBeforeLoad: record_gets });
		cy.wrap(gets).should((recorded) => {
			expect(recorded.some((get) => get.mediation === "conditional"), "conditional UI armed").to.eq(true);
		});
		cy.window()
			.then((win) => win.PublicKeyCredential.getClientCapabilities())
			.its("immediateGet")
			.should("eq", true);
	};

	it("signs in from this device's passkey through immediate UI mode", () => {
		cy.stub_post_login_shell();
		cy.intercept_frappe_method("passkeys.passkey.verify_login", "verify");
		visit_with_conditional_armed();
		cy.get("#passkey-login-btn").real_click();
		cy.wait("@verify", { timeout: 20000 }).its("response.statusCode").should("be.within", 200, 299);
		cy.then(() => {
			expect(button_gets().map((get) => get.ui_mode), "one immediate request").to.deep.eq(["immediate"]);
			const autofill = gets.filter((get) => get.mediation === "conditional");
			expect(autofill.every((get) => get.is_aborted()), "autofill request aborted first").to.eq(true);
		});
		cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk)/);
		cy.assert_logged_user(USER);
	});

	it("with no passkey on this device, opens the full sheet in the same click on the same ceremony", () => {
		cy.clear_virtual_credentials();
		visit_with_conditional_armed();
		cy.get("#passkey-login-btn").real_click();
		cy.wrap(gets).should(() => {
			const requests = button_gets();
			expect(requests.map((get) => get.ui_mode), "immediate, then the full sheet").to.deep.eq([
				"immediate",
				undefined,
			]);
			// begin_login mints a fresh challenge, so the same one means no new ceremony.
			expect(requests[1].challenge, "the same ceremony").to.eq(requests[0].challenge);
		});
		// The empty authenticator then fails the full sheet like a closed one.
		cy.get("#passkey-login-status").should("contain", "No passkey was used");
	});
});
