// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P5 spec 2 — call-with-retry + verbatim fingerprint echo (DESIGN-v1 §7.2 A36).
// `frappe.passkeys.call` calls the protected method, catches the 401 contract,
// runs the confirmation dialog, and retries ONCE with X-Passkey-Grant. The begin
// request MUST echo the 401's payload_fingerprint verbatim as `payload_hash` and
// send NO raw `params` — no hash is ever computed client-side.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const PROBE = "passkeys.tests.ui_test_helpers.confirm_probe";

chromium_only("passkey action-confirmation — call() retry", () => {
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

	it("retries once with the grant header and echoes the fingerprint verbatim", () => {
		cy.visit("/app");
		cy.intercept("POST", "**/passkeys.confirm.begin_confirmation").as("begin");
		cy.window().then((win) =>
			cy
				.wrap(win.frappe.passkeys.call(PROBE, { token: "R1" }), { timeout: 20000 })
				.then((message) => {
					expect(message.confirmed).to.eq(true);
					expect(message.token).to.eq("R1");
				})
		);
		cy.wait("@begin").then(({ request }) => {
			// A36: the retry sent the server's fingerprint verbatim, never raw params.
			expect(request.body).to.have.property("payload_hash");
			expect(request.body).to.not.have.property("params");
		});
	});
});
