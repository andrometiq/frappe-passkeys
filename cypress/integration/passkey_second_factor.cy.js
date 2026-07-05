// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P4 spec — password → passkey second factor (DESIGN-v1 §6, §12.3). Three
// journeys against the real committed bundle + a CDP virtual authenticator:
//   1. password submit → passkey step-up dialog → session (dispatch, not stacked
//      onto OTP);
//   2. the OTP-fallback secondary action hands off to core's own OTP UI
//      (`#login_token`) when passkey_2fa_allow_otp_fallback is on;
//   3. a failed leg-2 verify re-arms a fresh state and a second gesture succeeds
//      WITHOUT ever re-POSTing an assertion (§6.3 / A37).
//
// The second factor is hard-exempt for Administrator (§6.2), so these run as a
// dedicated non-admin user registered while a first-factor mode is on, then
// covered by a core-2FA role once the passkey exists.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;

const SF_USER = "passkey-sf-ui@example.com";
const SF_PW = "Secret_passw0rd_9x!";
const ADMIN_PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("password → passkey second factor", () => {
	before(() => {
		cy.enable_virtual_authenticator();

		// 1. as admin: enable a first-factor mode + create the user, so the
		//    committed registration ceremony can seed a real resident credential.
		cy.login("Administrator", ADMIN_PW());
		cy.visit("/app");
		cy.setup_passkey_settings({ second_factor: false });
		cy.ensure_sf_user(SF_USER, SF_PW);
		cy.purge_server_passkeys(SF_USER);

		// 2. register a passkey AS the user (still 2FA-uncovered ⇒ plain login).
		cy.register_passkey(SF_USER, SF_PW);

		// 3. flip the site to second-factor mode (core 2FA ON is the floor) and
		//    cover the user with a 2FA role AFTER the passkey exists.
		cy.login("Administrator", ADMIN_PW());
		cy.visit("/app");
		cy.setup_second_factor({ first_factor: false, otp_fallback: true });
		cy.enroll_user_2fa(SF_USER);
		cy.call("logout");
	});

	after(() => {
		cy.login("Administrator", ADMIN_PW());
		cy.visit("/app");
		cy.teardown_second_factor();
		cy.delete_test_user(SF_USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	beforeEach(() => {
		cy.clearCookies();
	});

	function submitPassword() {
		cy.visit("/login");
		cy.get("#login_email").clear().type(SF_USER);
		cy.get("#login_password").clear().type(SF_PW, { log: false });
		cy.get(".form-login").first().submit();
		cy.get(".passkey-dialog", { timeout: 15000 }).should("be.visible");
	}

	it("password submit drives the passkey step-up and mints a session", () => {
		submitPassword();
		cy.contains(".passkey-dialog button", "Use a passkey").click();
		cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk)/);
		cy.window().its("frappe.session.user").should("eq", SF_USER);
	});

	it("offers the OTP fallback and hands off to core's OTP UI", () => {
		submitPassword();
		// the secondary action exists only because passkey_2fa_allow_otp_fallback
		// is on AND the user is OTP-capable (server-gated, §6.3).
		cy.contains(".passkey-dialog button", "Use a verification code instead").click();
		// core's own OTP form paints its token input — the passkey app got out of
		// the way (dispatch to core's leg 2, no stacking).
		cy.get("#login_token", { timeout: 15000 }).should("exist");
	});

	it("re-arms on a failed passkey then succeeds on a fresh gesture (no re-POST)", () => {
		const sf = {};
		const assertionIds = [];
		let verifyCalls = 0;

		// capture leg 1's still-unconsumed state + options so the stubbed re-arm
		// can hand them back (the real state is untouched — the first verify is
		// short-circuited before it reaches the server).
		cy.intercept("POST", "**/passkeys.passkey.login_with_password", (req) => {
			req.continue((res) => {
				sf.tmpId = res.body.tmp_id;
				sf.options = res.body.verification && res.body.verification.options;
			});
		}).as("pw");

		cy.intercept("POST", "**/passkeys.passkey.verify_second_factor", (req) => {
			verifyCalls += 1;
			try {
				const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
				const cred = typeof body.credential === "string" ? JSON.parse(body.credential) : body.credential;
				assertionIds.push(cred && cred.id);
			} catch (e) {
				assertionIds.push(null);
			}
			if (verifyCalls === 1) {
				// server-shaped re-arm: CeremonyExpired + a fresh state_id/options
				// (here the still-live leg-1 pair) — the bundle retries on it.
				req.reply({
					statusCode: 401,
					body: {
						exc_type: "CeremonyExpired",
						exception: "CeremonyExpired",
						state_id: sf.tmpId,
						verification: { method: "Passkey", options: sf.options },
					},
				});
			}
			// verifyCalls === 2 falls through to the real server (consumes leg 1).
		}).as("verify_sf");

		submitPassword();
		cy.contains(".passkey-dialog button", "Use a passkey").click();
		// re-arm keeps the dialog open with an inline error; a fresh gesture retries
		cy.get(".passkey-dialog .passkey-dialog-error", { timeout: 15000 }).should("not.be.empty");
		cy.contains(".passkey-dialog button", "Use a passkey").click();

		cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk)/);
		cy.window().its("frappe.session.user").should("eq", SF_USER);

		cy.then(() => {
			expect(verifyCalls, "a second verify happened").to.be.greaterThan(1);
			const nonNull = assertionIds.filter(Boolean);
			// each verify carried a freshly-minted assertion — never a replay
			expect(new Set(nonNull).size, "no assertion was re-POSTed").to.eq(nonNull.length);
		});
	});
});
