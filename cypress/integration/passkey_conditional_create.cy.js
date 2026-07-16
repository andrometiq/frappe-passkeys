// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Conditional create (silent enrollment after a PASSWORD login).
// After an interactive password login the Desk bundle's post-login check runs a
// `navigator.credentials.create({ mediation: "conditional" })` with NO dialog when:
//   server knob `passkey_conditional_create` on ∧ 0 credentials ∧ nudge eligible ∧
//   `getClientCapabilities().conditionalCreate === true` ∧ post_login_method ===
//   "password" (passkey_manage_common `nudgeDecision`). Headless Chromium
//   does not give Cypress a deterministic way to pick the silent conditional-create
//   credential, so the test first proves the app asked for `mediation:"conditional"`
//   and then fulfills the same registration options with a standard virtual-auth
//   create to prove verify_registration and the server row.
// The ABSENCE half is enforced server-side: an email-link / OAuth login leaves only
// a WEAK sudo window (never "password"), so `begin_registration(flow=
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
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		// conditional_create ON, nudge ON — the silent-create branch takes precedence
		// over the visible nudge (maybeNudge).
		cy.call(CONFIGURE_NUDGE, {
			enrollment_nudge: 1,
			max_prompts: 3,
			cooldown_days: 30,
			conditional_create: 1,
		});
	});

	after(() => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	beforeEach(() => {
		// credential_count must be 0 for eligibility; reset the cadence too.
		cy.login(USER, PW());
		cy.purge_server_passkeys(USER);
		cy.clear_virtual_credentials();
		cy.call(SEED_NUDGE, { declines: 0, last_shown: null, opt_out: 0 });
	});

	it("arms conditional-create and completes registration after a password login", function () {
		// getClientCapabilities().conditionalCreate is REQUIRED for the client to
		// attempt a silent create (the create must be certain-capable). Skip
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

		cy.intercept_frappe_method("passkeys.api.registration.begin_registration", "begin_registration");
		cy.intercept_frappe_method("passkeys.api.registration.verify_registration", "verify_registration");
		cy.login(USER, PW()); // password login → password window + post_login_method
		cy.visit_desk(USER, {
			onBeforeLoad(win) {
				const creds = win.navigator && win.navigator.credentials;
				const nativeCreate = creds && creds.create && creds.create.bind(creds);
				win.__passkey_create_calls = [];
				if (!nativeCreate) return;
				Object.defineProperty(creds, "create", {
					configurable: true,
					value(options) {
						win.__passkey_create_calls.push(options);
						if (options && options.mediation === "conditional") {
							// The conditional browser request is asserted from the
							// recorded options; deterministic headless completion uses
							// the same publicKey through standard virtual WebAuthn.
							return nativeCreate({ publicKey: options.publicKey });
						}
						return nativeCreate(options);
					},
				});
			},
		}); // Desk boot runs maybeNudge → silent conditionalCreate()
		cy.wait("@begin_registration", { timeout: 15000 }).its("response.statusCode").should("be.within", 200, 299);
		cy.window().should((win) => {
			const calls = win.__passkey_create_calls || [];
			const call = calls.find((entry) => entry && entry.mediation === "conditional");
			expect(call, "conditional create call").to.exist;
			expect(call.publicKey, "publicKey options").to.exist;
			expect(call.signal, "abort signal").to.exist;
		});
		cy.wait("@verify_registration", { timeout: 20000 })
			.its("response.statusCode")
			.should("be.within", 200, 299);
		cy.call(CRED_COUNT, { user: USER }).then((r) => {
			expect(unwrap(r)).to.eq(1);
		});
	});

	it("refuses conditional-create when the login left no password-grade window", () => {
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.window().its("frappe").should("exist");
		// An email-link / OAuth login seeds only a WEAK sudo window (never "password");
		// reproduce that freshness gap by clearing this session's window. The
		// silent conditional-create ceremony must then be REFUSED server-side.
		cy.call(CLEAR_WINDOW, {});
		cy.window()
			.its("frappe.csrf_token")
			.then((csrf) => {
				cy.request({
					url: "/api/method/passkeys.api.registration.begin_registration",
					method: "POST",
					body: { flow: "conditional_create" },
					headers: { "X-Frappe-CSRF-Token": csrf, Accept: "application/json" },
					failOnStatusCode: false,
				}).then((res) => {
					// the PasskeyConfirmationRequired retry contract, not a ceremony
					expect(res.status).to.be.gte(400);
				});
			});
		// ...and nothing was silently enrolled off the non-password login
		cy.call(CRED_COUNT, { user: USER }).then((r) => {
			expect(unwrap(r)).to.eq(0);
		});
	});
});
