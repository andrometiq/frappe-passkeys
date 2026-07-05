// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P5 spec 4 — confirmation dialog accessibility (DESIGN-v1 §5.5/§7.3). The dialog
// is role="dialog" + aria-labelledby, traps focus, is Esc-dismissable (→
// user_cancelled), exposes an aria-live outcome region, and returns focus to the
// invoking control after close.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const ACTION = "passkeys.tests.confirm_probe";

chromium_only("passkey action-confirmation — accessibility", () => {
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

	it("is a labelled modal dialog, Esc-cancels, and returns focus to the opener", () => {
		cy.visit("/app");
		cy.hold_passkey_taps(); // keep the ceremony pending → the dialog stays open
		cy.window().then((win) => {
			// an invoking control that owns focus before the dialog opens
			win.document.body.insertAdjacentHTML(
				"beforeend",
				'<button id="confirm-opener">go</button>'
			);
			win.document.getElementById("confirm-opener").focus();
			win.__confirm_reject = null;
			win.frappe.passkeys
				.confirm(ACTION, { token: "A1" })
				.catch((err) => (win.__confirm_reject = err));
		});

		cy.get(".passkey-dialog")
			.should("have.attr", "role", "dialog")
			.and("have.attr", "aria-labelledby");
		cy.get(".passkey-dialog [aria-live]").should("exist");

		cy.get("body").type("{esc}");
		cy.get(".passkey-dialog").should("not.exist");
		cy.focused().should("have.id", "confirm-opener");
		cy.window().its("__confirm_reject.code").should("eq", "user_cancelled");
		cy.simulate_passkey_tap();
	});
});
