// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Action-confirmation happy path. The low-level
// `frappe.passkeys.confirm(action, params)` runs the ceremony (begin → virtual UV
// assertion → verify_confirmation) and resolves to a grant TOKEN; attaching it as
// the X-Passkey-Grant header authorizes the @passkey_protected probe endpoint.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const PROBE = "passkeys.tests.ui_test_helpers.confirm_probe";
const ACTION = "passkeys.tests.confirm_probe";

chromium_only("passkey action-confirmation — happy path", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
		cy.login(USER, PW());
	});

	after(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("confirm(action, params) resolves a grant token that authorizes the action", () => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.window().its("frappe.passkeys").should("exist");
		cy.window().then((win) => {
			const p = win.frappe.passkeys.confirm(ACTION, { token: "T1" });
			cy.get(".passkey-confirm-passkey").should("be.visible").click();
			return cy.wrap(p, { timeout: 20000 }).then((grant) => {
				expect(grant, "grant token").to.be.a("string").and.have.length.greaterThan(10);
				return cy
					.wrap(
						win.frappe.call({
							method: PROBE,
							args: { token: "T1" },
							headers: { "X-Passkey-Grant": grant },
						})
					)
					.then((r) => {
						expect(r.message.confirmed).to.eq(true);
						expect(r.message.token).to.eq("T1");
					});
			});
		});
	});
});
