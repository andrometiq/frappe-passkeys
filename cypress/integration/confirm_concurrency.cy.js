// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P5 spec 6 — concurrency shares one ceremony (DESIGN-v1 §7.3 A44). Two identical
// concurrent invocations share ONE in-flight dialog/ceremony — never two stacked
// dialogs racing one gesture. Asserted by counting begin_confirmation requests: one.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const PROBE = "passkeys.tests.ui_test_helpers.confirm_probe";

chromium_only("passkey action-confirmation — concurrency", () => {
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

	it("two identical concurrent call()s share a single ceremony", () => {
		cy.visit("/app");
		let begins = 0;
		cy.intercept("POST", "**/passkeys.confirm.begin_confirmation", (req) => {
			begins += 1;
			req.continue();
		});
		cy.window().then((win) => {
			const args = { token: "C1" };
			const both = Promise.all([
				win.frappe.passkeys.call(PROBE, args),
				win.frappe.passkeys.call(PROBE, args),
			]);
			return cy.wrap(both, { timeout: 20000 }).then(([a, b]) => {
				expect(a.confirmed).to.eq(true);
				expect(b.confirmed).to.eq(true);
				expect(begins, "one shared begin_confirmation").to.eq(1);
				cy.get(".passkey-dialog").should("not.exist");
			});
		});
	});
});
