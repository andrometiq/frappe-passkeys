// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P5 spec 5 — rejection taxonomy (DESIGN-v1 §7.3 A44). Both helpers reject with a
// fixed, exhaustive {code}: user_cancelled (NotAllowedError / timeout), no_credentials,
// not_supported (417 PasskeyServedByCore), network (offline). Codes are what
// consuming apps program against.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const ACTION = "passkeys.tests.confirm_probe";

const reject_code = (win, promise) =>
	promise.then(
		() => {
			throw new Error("expected rejection");
		},
		(err) => err && err.code
	);

chromium_only("passkey action-confirmation — error taxonomy", () => {
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

	it("maps a cancelled OS sheet to user_cancelled", () => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.window().then((win) => {
			const err = new Error("cancelled");
			err.name = "NotAllowedError";
			cy.stub(win.navigator.credentials, "get").rejects(err);
			win.__passkey_confirm_reject = reject_code(
				win,
				win.frappe.passkeys.confirm(ACTION, { token: "E1" })
			);
		});
		cy.get(".passkey-confirm-passkey").should("be.visible").click();
		cy.window().then((win) =>
			cy.wrap(win.__passkey_confirm_reject, { timeout: 20000 }).should("eq", "user_cancelled")
		);
	});

	it("maps an offline transport failure to network", () => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.intercept("POST", "**/passkeys.confirm.begin_confirmation", { forceNetworkError: true });
		cy.window().then((win) =>
			cy
				.wrap(reject_code(win, win.frappe.passkeys.confirm(ACTION, { token: "E2" })), {
					timeout: 20000,
				})
				.should("eq", "network")
		);
	});
});
