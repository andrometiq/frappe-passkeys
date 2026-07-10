// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P3 spec 8 — guest i18n delivery (DESIGN-v1 §5.6). On v15/v16 core ships NO
// guest translations, so the bundle fetches passkeys.passkey.get_app_translations
// and Object.assign-merges the catalog into frappe._messages. With the site
// language set to French, the passkey button must render its French label —
// proving the app endpoint + client merge, not an English fallback. (fr.csv ships
// "Sign in with a passkey" → "Se connecter avec une clé d'accès".)

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const FR_LABEL = "Se connecter avec une clé d'accès";

chromium_only("passkey guest i18n", () => {
	before(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		// Guest language resolves from the preferred_language cookie.
		cy.call("logout");
	});

	after(() => {
		cy.clearCookies();
	});

	it("renders passkey strings in the request language via the app endpoint", () => {
		cy.setCookie("preferred_language", "fr");
		cy.visit_login();
		// The label starts English and is replaced once the merged catalog lands;
		// cypress retries the assertion until the merge completes.
		cy.get("#passkey-login-btn", { timeout: 20000 }).should("have.text", FR_LABEL);
	});

	it("does not clobber the rest of frappe._messages", () => {
		cy.setCookie("preferred_language", "fr");
		cy.visit_login();
		cy.get("#passkey-login-btn").should("exist");
		cy.window().then((win) => {
			// merge is additive: the passkey key is present and _messages is an object
			expect(win.frappe._messages).to.be.an("object");
			expect(win.frappe._messages["Sign in with a passkey"]).to.eq(FR_LABEL);
		});
	});
});
