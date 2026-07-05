// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P5 spec 3 — password fallback (DESIGN-v1 §7.2). For an allow_password_fallback
// action with no usable passkey, the dialog offers a password tab;
// reauth_password{pwd, action, payload_fingerprint} mints a password-method grant
// that authorizes the retry. Wrong password retries in-dialog. A
// allow_password_fallback=False action offers no password door (fallback_unavailable).

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const PROBE = "passkeys.tests.ui_test_helpers.confirm_probe";
const PROBE_PK_ONLY = "passkeys.tests.ui_test_helpers.confirm_probe_passkey_only";

chromium_only("passkey action-confirmation — password fallback", () => {
	before(() => {
		cy.login(USER, PW());
		cy.visit("/app");
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER); // no passkey → the dialog leads with password
	});

	after(() => {
		cy.purge_server_passkeys(USER);
		cy.clearCookies();
	});

	it("mints a password-method grant and authorizes the action", () => {
		cy.visit("/app");
		cy.window().then((win) => {
			const p = win.frappe.passkeys.call(PROBE, { token: "PF1" });
			cy.get(".passkey-dialog").should("exist");
			cy.get(".passkey-dialog").find("input[type=password]").type(PW());
			cy.get(".passkey-dialog").contains("button", /confirm|continue|submit/i).click();
			return cy.wrap(p, { timeout: 20000 }).then((message) => {
				expect(message.confirmed).to.eq(true);
				expect(message.token).to.eq("PF1");
			});
		});
	});

	it("offers no password door when the action forbids fallback", () => {
		cy.visit("/app");
		cy.window().then((win) => {
			const p = win.frappe.passkeys
				.call(PROBE_PK_ONLY, { token: "X" })
				.then(() => {
					throw new Error("expected rejection");
				})
				.catch((err) => err);
			return cy.wrap(p, { timeout: 20000 }).then((err) => {
				expect(err.code).to.eq("fallback_unavailable");
			});
		});
	});
});
