// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P6 spec — enrollment-nudge cadence UX (DESIGN-v1 §8.4). The post-login nudge
// shows on Desk boot only when: the nudge knob is on ∧ credential_count == 0 ∧
// detection passes ∧ server-side cadence allows (declines < max_prompts ∧
// last_shown ≥ cooldown ∧ not opted out). Counters are SERVER-side per-user, so a
// user gets N prompts total, never N-per-browser. "Not now" records a decline;
// "Don't ask again" opts out. Needs nudge test helpers — see the manifest.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const CONFIGURE_NUDGE = "passkeys.tests.ui_test_helpers.configure_nudge";
const SEED_NUDGE = "passkeys.tests.ui_test_helpers.seed_nudge_state";
const GET_NUDGE = "passkeys.tests.ui_test_helpers.get_nudge_state";

chromium_only("passkey enrollment nudge — cadence", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit("/app");
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER); // credential_count must be 0 for the nudge
		cy.call(CONFIGURE_NUDGE, { enrollment_nudge: 1, max_prompts: 3, cooldown_days: 30, conditional_create: 0 });
	});

	after(() => {
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	beforeEach(() => {
		cy.call(SEED_NUDGE, { declines: 0, last_shown: null, opt_out: 0 });
	});

	it("shows the convenience-first nudge dialog with the three affordances", () => {
		cy.login(USER, PW());
		cy.visit("/app");
		cy.get(".modal-dialog", { timeout: 20000 }).should("be.visible");
		cy.get(".modal-dialog .modal-title").should("contain.text", "Sign in faster next time");
		cy.get(".modal-dialog").within(() => {
			cy.contains("Create a passkey").should("exist");
			cy.contains("Not now").should("exist");
			cy.contains("Don't ask again").should("exist");
		});
	});

	it("'Not now' records a server-side decline", () => {
		cy.login(USER, PW());
		cy.visit("/app");
		cy.get(".modal-dialog", { timeout: 20000 }).contains("Not now").click();
		cy.call(GET_NUDGE, {}).then((state) => {
			expect((state.message || state).declines).to.be.greaterThan(0);
		});
	});

	it("'Don't ask again' opts out — no nudge on the next login", () => {
		cy.login(USER, PW());
		cy.visit("/app");
		cy.get(".modal-dialog", { timeout: 20000 }).contains("Don't ask again").click();
		cy.call(GET_NUDGE, {}).then((state) => {
			expect((state.message || state).opt_out).to.eq(1);
		});
		cy.login(USER, PW());
		cy.visit("/app");
		// give the boot nudge check time to run and NOT open a dialog
		cy.wait(1500);
		cy.get(".modal-dialog .modal-title:contains('Sign in faster next time')").should("not.exist");
	});

	it("stops nudging once the decline cap is reached (server counters)", () => {
		cy.call(SEED_NUDGE, { declines: 3, last_shown: null, opt_out: 0 });
		cy.login(USER, PW());
		cy.visit("/app");
		cy.wait(1500);
		cy.get(".modal-dialog .modal-title:contains('Sign in faster next time')").should("not.exist");
	});
});
