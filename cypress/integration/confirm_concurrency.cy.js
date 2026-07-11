// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Concurrency shares one ceremony. Two identical
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

	it("two identical concurrent call()s share one ceremony but only one single-use grant", () => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		let begins = 0;
		cy.intercept("POST", "**/passkeys.confirm.begin_confirmation", (req) => {
			begins += 1;
			req.continue();
		});
		cy.window().then((win) => {
			const args = { token: "C1" };
			win.__passkey_confirm_results = Promise.allSettled([
				win.frappe.passkeys.call(PROBE, args),
				win.frappe.passkeys.call(PROBE, args),
			]);
		});
		cy.get(".modal.show").should("be.visible");
		cy.get(".passkey-confirm-passkey").should("be.visible").click();
		cy.window().then((win) =>
			cy.wrap(win.__passkey_confirm_results, { timeout: 20000 }).then((results) => {
				const fulfilled = results.filter((r) => r.status === "fulfilled");
				const rejected = results.filter((r) => r.status === "rejected");
				expect(fulfilled, "one retried action uses the grant").to.have.length(1);
				expect(rejected, "the second retry cannot reuse the grant").to.have.length(1);
				expect(fulfilled[0].value.confirmed).to.eq(true);
				expect(rejected[0].reason.code).to.eq("confirmation_failed");
				expect(begins, "one shared begin_confirmation").to.eq(1);
			})
		);
		cy.get(".modal.show", { timeout: 10000 }).should("not.exist");
		cy.get(".passkey-confirm").should("not.be.visible");
	});
});
