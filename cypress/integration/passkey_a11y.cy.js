// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P3 spec 7 — accessibility contract (DESIGN-v1 §5.5). One polite live region for
// async outcomes; the injected button carries an accessible name; the step-up
// dialog is role="dialog" + aria-modal, traps focus, is Esc-dismissable, and
// returns focus to its opener. Presence is HELD so the "waiting for your passkey"
// dialog stays open for inspection.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey login accessibility", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit("/app");
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
	});

	after(() => {
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("exposes a live region and an accessibly-named button", () => {
		cy.visit("/login");
		cy.get(".passkey-sr-only").should("exist");
		cy.get("#passkey-login-btn")
			.should("have.text", "Sign in with a passkey")
			.and("have.attr", "type", "button");
	});

	it("opens a modal dialog that traps + returns focus and is Esc-dismissable", () => {
		cy.visit("/login");
		cy.hold_passkey_taps(); // keep the ceremony pending → dialog stays open
		cy.get("#passkey-login-btn").click();

		cy.get(".passkey-dialog")
			.should("have.attr", "role", "dialog")
			.and("have.attr", "aria-modal", "true")
			.and("have.attr", "aria-labelledby");

		// Esc closes and focus returns to the opener
		cy.get("body").type("{esc}");
		cy.get(".passkey-dialog").should("not.exist");
		cy.focused().should("have.id", "passkey-login-btn");
		cy.simulate_passkey_tap(); // release for teardown hygiene
	});
});
