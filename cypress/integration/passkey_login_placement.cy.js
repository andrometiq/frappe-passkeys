// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// DOM-placement / contract. The single highest-value
// per-branch guard: it asserts the bundle finds its mount points on the ACTUAL
// login markup of the branch under test (this file runs on develop's redesigned
// card; the v15/v16 CI cells assert the older layout). If core reshuffles the
// login template, this is the spec that goes red first.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey login DOM contract", () => {
	before(() => {
		cy.login(USER, PW());
		cy.setup_passkey_settings();
	});

	after(() => cy.clearCookies());

	it("mounts the button and patches the username field on this branch markup", () => {
		cy.visit_login();
		// button mount point resolved (.btn-login-option / .social-logins / form)
		cy.get("#passkey-login-btn").should("exist");
		cy.get(".form-login, form.form-signin").should("exist");
		// conditional-UI username patch applied
		cy.get("#login_email")
			.should("have.attr", "autocomplete")
			.and("match", /\bwebauthn\b/);
		// the injected control carries an accessible name + glyph is decorative
		cy.get("#passkey-login-btn .passkey-glyph").should("have.attr", "aria-hidden", "true");
		cy.get("#passkey-login-btn .passkey-label").should("contain", "passkey");
	});

	it("keeps a usable password form alongside the passkey affordance", () => {
		cy.visit_login();
		cy.get("#login_email").should("be.visible");
		cy.get("#login_password").should("exist");
	});
});
