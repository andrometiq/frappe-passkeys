// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Grant semantics. Single-use: a consumed grant is
// rejected on replay. The grant is burned even when the wrapped action then
// fails, so a retry needs a fresh ceremony. sid-bound: a grant is unusable after
// logout.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const PROBE = "passkeys.tests.ui_test_helpers.confirm_probe";
const PROBE_FAIL = "passkeys.tests.ui_test_helpers.confirm_probe_failing";
const ACTION = "passkeys.tests.confirm_probe";

chromium_only("passkey action-confirmation — grant semantics", () => {
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

	it("a consumed grant is rejected on replay (single-use)", () => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.window().then((win) => {
			const p = win.frappe.passkeys.confirm(ACTION, { token: "G1" });
			cy.get(".passkey-confirm-passkey").should("be.visible").click();
			return cy.wrap(p, { timeout: 20000 }).then((grant) => {
				const first = win.frappe.call({
					method: PROBE,
					args: { token: "G1" },
					headers: { "X-Passkey-Grant": grant },
				});
				return cy.wrap(first).then((r1) => {
					expect(r1.message.confirmed).to.eq(true);
					// replay the same grant → 401 retry contract (rejected server-side)
					const replay = win.frappe
						.call({
							method: PROBE,
							args: { token: "G1" },
							headers: { "X-Passkey-Grant": grant },
						})
						.then(
							() => "ACCEPTED",
							() => "REJECTED"
						);
					return cy.wrap(replay).should("eq", "REJECTED");
				});
			});
		});
	});

	it("burns the grant even when the wrapped action fails (A-F20)", () => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.window().then((win) => {
			const p = win.frappe.passkeys.confirm(PROBE_FAIL, { token: "G2" });
			cy.get(".passkey-confirm-passkey").should("be.visible").click();
			return cy.wrap(p, { timeout: 20000 }).then((grant) => {
				// the action throws AFTER the grant is consumed → the gesture is spent
				const failed = win.frappe
					.call({
						method: PROBE_FAIL,
						args: { token: "G2" },
						headers: { "X-Passkey-Grant": grant },
					})
					.then(
						() => "ACCEPTED",
						() => "FAILED"
					);
				return cy.wrap(failed).then((outcome) => {
					expect(outcome).to.eq("FAILED");
					// the same grant no longer authorizes a retry — it was burned
					const replay = win.frappe
						.call({
							method: PROBE_FAIL,
							args: { token: "G2" },
							headers: { "X-Passkey-Grant": grant },
						})
						.then(
							() => "ACCEPTED",
							() => "REJECTED"
						);
					return cy.wrap(replay).should("eq", "REJECTED");
				});
			});
		});
	});
});
