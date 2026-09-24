// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Guest i18n delivery. On v15/v16 core ships no guest translations, so the
// bundle fetches passkeys.passkey.get_app_translations and merges the catalog
// into frappe._messages. A test-only Translation row for the request language
// must replace the English button label — proving the app endpoint and the
// client merge, not an English fallback.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const SOURCE = "Sign in with a passkey";
const LABEL = "TEST-ONLY passkey sign-in";
const SET = "passkeys.tests.ui_test_helpers.set_test_translation";
const CLEAR = "passkeys.tests.ui_test_helpers.clear_test_translation";

chromium_only("passkey guest i18n", () => {
	let translationName = null;

	before(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.clear_guest_ceremony_rate_limit();
		cy.call(SET, { source: SOURCE, translated: LABEL, language: "de" }).then((res) => {
			const message = res.message !== undefined ? res.message : res;
			translationName = message.name;
		});
		cy.call("logout");
	});

	after(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.then(() => {
			if (translationName) cy.call(CLEAR, { name: translationName });
		});
		cy.clearCookies();
	});

	it("renders passkey strings in the request language via the app endpoint", () => {
		cy.setCookie("preferred_language", "de");
		cy.visit_login();
		// The label starts English and is replaced once the merged catalog lands;
		// cypress retries the assertion until the merge completes.
		cy.get("#passkey-login-btn", { timeout: 20000 }).should("have.text", LABEL);
	});

	it("does not clobber the rest of frappe._messages", () => {
		cy.setCookie("preferred_language", "de");
		cy.visit_login();
		cy.get("#passkey-login-btn").should("exist");
		cy.window().then((win) => {
			expect(win.frappe._messages).to.be.an("object");
			expect(win.frappe._messages[SOURCE]).to.eq(LABEL);
		});
	});
});
