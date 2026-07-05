// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P3 spec 10 — no WebAuthn support (DESIGN-v1 §5.2 layered detection). When
// window.PublicKeyCredential is absent, the bundle must no-op cleanly: no passkey
// button, no thrown error, password login intact. Simulated by deleting the
// WebAuthn globals before the app scripts run.

const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

// This spec is browser-agnostic (it removes WebAuthn), so it does not need the
// chromium/virtual-authenticator guard.
describe("passkey login without WebAuthn support", () => {
	before(() => {
		cy.login(USER, PW());
		cy.visit("/app");
		cy.setup_passkey_settings();
		cy.call("logout");
	});

	after(() => cy.clearCookies());

	it("no-ops with no button and a working password form", () => {
		cy.visit("/login", {
			onBeforeLoad(win) {
				// Strip WebAuthn so layered detection short-circuits.
				try {
					delete win.PublicKeyCredential;
				} catch (e) {
					win.PublicKeyCredential = undefined;
				}
				if (win.navigator && win.navigator.credentials) {
					try {
						delete win.navigator.credentials;
					} catch (e) {
						/* read-only in some engines — the PublicKeyCredential delete is the gate */
					}
				}
			},
		});
		cy.get("#login_email").should("be.visible");
		cy.get("#passkey-login-btn").should("not.exist");
		cy.get(".login-error-banner:visible").should("not.exist");

		// password login remains fully functional
		cy.get("#login_email").type(USER);
		cy.get("#login_password").type(PW());
		cy.get(".btn-login").first().click();
		cy.location("pathname", { timeout: 20000 }).should("match", /^\/(app|desk)/);
	});
});
