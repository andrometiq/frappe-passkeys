// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P3/P6 spec — §8.4 conditional create (silent enrollment after a PASSWORD login).
// After an interactive password login the Desk bundle's post-login check runs a
// `navigator.credentials.create({ mediation: "conditional" })` with NO dialog when:
//   server knob `passkey_conditional_create` on ∧ 0 credentials ∧ nudge eligible ∧
//   `getClientCapabilities().conditionalCreate === true` ∧ post_login_method ===
//   "password" (§8.4 / passkey_manage_common `nudgeDecision`). The silent ceremony
//   enrolls a real resident credential → the server row appears.
// The ABSENCE half is enforced server-side: an email-link / OAuth login leaves only
// a WEAK sudo window (never "password", §7.1), so `begin_registration(flow=
// conditional_create)` is refused — no passkey can be silently minted off a
// non-password login. CI-gated (CDP virtual authenticator); not run locally.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const CONFIGURE_NUDGE = "passkeys.tests.ui_test_helpers.configure_nudge";
const SEED_NUDGE = "passkeys.tests.ui_test_helpers.seed_nudge_state";
const CRED_COUNT = "passkeys.tests.ui_test_helpers.credential_count";
const CLEAR_WINDOW = "passkeys.tests.ui_test_helpers.clear_sudo_window";

const unwrap = (r) => (r && r.message !== undefined ? r.message : r);

chromium_only("passkey conditional create — silent post-password enrollment", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit("/app");
		cy.setup_passkey_settings();
		// conditional_create ON, nudge ON — the silent-create branch takes precedence
		// over the visible nudge (§8.4 maybeNudge).
		cy.call(CONFIGURE_NUDGE, {
			enrollment_nudge: 1,
			max_prompts: 3,
			cooldown_days: 30,
			conditional_create: 1,
		});
	});

	after(() => {
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	beforeEach(() => {
		// credential_count must be 0 for eligibility; reset the cadence too.
		cy.purge_server_passkeys(USER);
		cy.clear_virtual_credentials();
		cy.call(SEED_NUDGE, { declines: 0, last_shown: null, opt_out: 0 });
	});

	it("silently enrolls a passkey via conditional-create after a password login", function () {
		// getClientCapabilities().conditionalCreate is REQUIRED for the client to
		// attempt a silent create (§8.4 — the create must be certain-capable). Skip
		// on a runner whose Chromium can't report it; a modern CI Chromium exercises
		// it. (The server gate is pinned unconditionally in the next test.)
		cy.window()
			.then((win) => {
				const PKC = win.PublicKeyCredential;
				if (!PKC || typeof PKC.getClientCapabilities !== "function") return false;
				return Promise.resolve()
					.then(() => PKC.getClientCapabilities())
					.then((c) => !!(c && c.conditionalCreate))
					.catch(() => false);
			})
			.then((capable) => {
				if (!capable) this.skip();
			});

		cy.login(USER, PW()); // password login → password window + post_login_method
		cy.visit("/app"); // Desk boot runs maybeNudge → silent conditionalCreate()
		cy.wait(3000); // let the silent begin→create→verify ceremony complete
		cy.call(CRED_COUNT, { user: USER }).then((r) => {
			expect(unwrap(r)).to.be.gte(1); // a resident credential was silently minted
		});
	});

	it("refuses conditional-create when the login left no password-grade window", () => {
		cy.login(USER, PW());
		cy.visit("/app");
		cy.window().its("frappe").should("exist");
		// An email-link / OAuth login seeds only a WEAK sudo window (never "password",
		// §7.1); reproduce that freshness gap by clearing this session's window. The
		// silent conditional-create ceremony must then be REFUSED server-side.
		cy.call(CLEAR_WINDOW, {});
		cy.window()
			.its("frappe.csrf_token")
			.then((csrf) => {
				cy.request({
					url: "/api/method/passkeys.passkey.begin_registration",
					method: "POST",
					body: { flow: "conditional_create" },
					headers: { "X-Frappe-CSRF-Token": csrf, Accept: "application/json" },
					failOnStatusCode: false,
				}).then((res) => {
					// the §7.2 PasskeyConfirmationRequired retry contract, not a ceremony
					expect(res.status).to.be.gte(400);
				});
			});
		// ...and nothing was silently enrolled off the non-password login
		cy.call(CRED_COUNT, { user: USER }).then((r) => {
			expect(unwrap(r)).to.eq(0);
		});
	});
});
