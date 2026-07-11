// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Confirmation dialog accessibility. The dialog
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

	it("is a labelled modal dialog, Esc-cancels, and returns focus to the opener", () => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
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

		cy.get(".modal.show").should(($modal) => {
			const modal = $modal[0];
			expect(modal.getAttribute("role"), "modal role").to.eq("dialog");
			expect(modal.querySelector(".passkey-confirm"), "passkey confirm body").to.exist;
			const title = modal.querySelector(".modal-title");
			expect(title && title.textContent.trim(), "dialog title").to.not.eq("");
		});
		cy.get(".modal.show .passkey-confirm-msg").should("have.attr", "aria-live", "polite");

		cy.focused().type("{esc}");
		cy.get(".modal.show").should("not.exist");
		cy.get(".passkey-confirm").should("not.be.visible");
		cy.focused().should("have.id", "confirm-opener");
		cy.window().its("__confirm_reject.code").should("eq", "user_cancelled");
		cy.simulate_passkey_tap();
	});
});
