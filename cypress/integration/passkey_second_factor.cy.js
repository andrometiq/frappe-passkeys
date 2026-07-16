// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Password → passkey second factor. Four
// journeys against the real committed bundle + a CDP virtual authenticator:
//   1. password submit → passkey step-up dialog → session (dispatch, not stacked
//      onto OTP);
//   2. the OTP-fallback secondary action hands off to core's own OTP UI
//      (`#login_token`) when passkey_2fa_allow_otp_fallback is on;
//   3. a failed leg-2 verify re-arms the UI and a second gesture succeeds WITHOUT
//      ever re-POSTing an assertion (fresh server re-arm is covered
//      by passkeys/tests/test_second_factor.py).
//   4. a non-401 server failure clears the pending state so a fresh gesture works.
//
// These run as a dedicated non-admin user registered while a first-factor mode is on, then
// covered by a core-2FA role once the passkey exists.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;

const SF_USER = `passkey-sf-ui-${Date.now()}@example.com`;
const SF_PW = "Secret_passw0rd_9x!";
const ADMIN_PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("password → passkey second factor", () => {
	before(() => {
		cy.enable_virtual_authenticator();

		// 1. as admin: enable a first-factor mode + create the user, so the
		//    committed registration ceremony can seed a real resident credential.
		cy.login("Administrator", ADMIN_PW());
		cy.visit_desk("Administrator");
		cy.setup_passkey_settings({ second_factor: false });
		cy.ensure_sf_user(SF_USER, SF_PW);
		cy.purge_server_passkeys(SF_USER);

		// 2. register a passkey AS the user (still 2FA-uncovered ⇒ plain login).
		cy.register_passkey(SF_USER, SF_PW, { surface: "portal" });

		// 3. flip the site to second-factor mode (core 2FA ON is the floor) and
		//    cover the user with a 2FA role AFTER the passkey exists.
		cy.login("Administrator", ADMIN_PW());
		cy.visit_desk("Administrator");
		cy.setup_second_factor({ first_factor: false, otp_fallback: true });
		cy.enroll_user_2fa(SF_USER);
		cy.call("logout");
	});

	after(() => {
		cy.login("Administrator", ADMIN_PW());
		cy.visit_desk("Administrator");
		cy.teardown_second_factor();
		cy.delete_test_user(SF_USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	beforeEach(() => {
		cy.clearCookies();
	});

	function submitPassword() {
		cy.intercept_frappe_method("passkeys.passkey.begin_login", "begin_login");
		cy.intercept_frappe_method("passkeys.passkey.login_with_password", "login_with_password");
		cy.visit_login();
		cy.wait("@begin_login", { timeout: 15000 }).then(({ response }) => {
			const body = response && response.body;
			const config = (body && (body.message || body)) || {};
			expect(config.enabled, "passkey login bundle is enabled").to.eq(true);
			expect(config.modes && config.modes.second_factor, "second-factor mode reached the browser").to.eq(
				true
			);
		});
		cy.get("html", { timeout: 15000 }).should(
			"have.attr",
			"data-passkeys-second-factor-ready",
			"true"
		);
		cy.get("#login_email").clear().type(SF_USER);
		cy.get("#login_password").clear().type(SF_PW, { log: false });
		cy.get(".form-login:visible")
			.find("button[type='submit']")
			.then(($button) => $button[0].click());
		cy.wait("@login_with_password", { timeout: 15000 }).then(({ response }) => {
			expect(response && response.statusCode, JSON.stringify(response && response.body)).to.eq(200);
		});
		cy.get(".passkey-dialog", { timeout: 15000 }).should("be.visible");
	}

	it("password submit drives the passkey step-up and mints a session", () => {
		cy.intercept_frappe_method("passkeys.passkey.verify_second_factor", "verify_sf");
		submitPassword();
		cy.contains(".passkey-dialog button", "Use a passkey").click();
		cy.wait("@verify_sf", { timeout: 20000 }).its("response.statusCode").should("eq", 200);
		cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk|me)/);
		cy.assert_logged_user(SF_USER);
	});

	it("offers the OTP fallback and hands off to core's OTP UI", () => {
		submitPassword();
		// the secondary action exists only because passkey_2fa_allow_otp_fallback
		// is on AND the user is OTP-capable (server-gated).
		cy.contains(".passkey-dialog button", "Use a verification code instead").click();
		// core's own OTP form paints its token input — the passkey app got out of
		// the way (dispatch to core's leg 2, no stacking).
		cy.get("#login_token", { timeout: 15000 }).should("exist");
	});

	it("re-arms on a failed passkey then succeeds on a fresh gesture (no re-POST)", () => {
		const sf = {};
		const assertionPayloads = [];
		let verifyCalls = 0;

		// capture leg 1's still-unconsumed state + options so the stubbed re-arm
		// can hand them back (the real state is untouched — the first verify is
		// short-circuited before it reaches the server).
		cy.intercept_frappe_method("passkeys.passkey.login_with_password", "pw", (req) => {
			req.continue((res) => {
				sf.tmpId = res.body.tmp_id;
				sf.options = res.body.verification && res.body.verification.options;
			});
		});

		cy.intercept_frappe_method("passkeys.passkey.verify_second_factor", "verify_sf", (req, body) => {
			verifyCalls += 1;
			try {
				const cred = typeof body.credential === "string" ? JSON.parse(body.credential) : body.credential;
				assertionPayloads.push(JSON.stringify(cred));
			} catch (e) {
				assertionPayloads.push(null);
			}
			if (verifyCalls === 1) {
				// server-shaped re-arm: CeremonyExpired + state_id/options. This client
				// spec reuses the still-live leg-1 pair so the second verify can fall
				// through to the real server; Python covers fresh server re-arm.
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
		});

		submitPassword();
		cy.contains(".passkey-dialog button", "Use a passkey").click();
		cy.wait("@verify_sf", { timeout: 20000 });
		// re-arm keeps the dialog open with an inline error; a fresh gesture retries
		cy.get(".passkey-dialog .passkey-dialog-error", { timeout: 15000 }).should("not.be.empty");
		cy.contains(".passkey-dialog button", "Use a passkey").click();
		cy.wait("@verify_sf", { timeout: 20000 });

		cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk|me)/);
		cy.assert_logged_user(SF_USER);

		cy.then(() => {
			expect(verifyCalls, "a second verify happened").to.be.greaterThan(1);
			const nonNull = assertionPayloads.filter(Boolean);
			expect(nonNull.length, "each verify payload was captured").to.eq(verifyCalls);
			// each verify carried a freshly-minted assertion — never a replay
			expect(new Set(nonNull).size, "no assertion was re-POSTed").to.eq(nonNull.length);
		});
	});

	it("allows a fresh gesture after a non-401 verification failure", () => {
		let verifyCalls = 0;
		cy.intercept_frappe_method("passkeys.passkey.verify_second_factor", "verify_sf", (req) => {
			verifyCalls += 1;
			if (verifyCalls === 1) {
				req.reply({ statusCode: 500, body: { exc_type: "InternalServerError" } });
			}
		});

		submitPassword();
		cy.contains(".passkey-dialog button", "Use a passkey").click();
		cy.wait("@verify_sf", { timeout: 20000 }).its("response.statusCode").should("eq", 500);
		cy.get(".passkey-dialog .passkey-dialog-error", { timeout: 15000 }).should("not.be.empty");
		cy.contains(".passkey-dialog button", "Use a passkey").click();
		cy.wait("@verify_sf", { timeout: 20000 }).its("response.statusCode").should("eq", 200);

		cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk|me)/);
		cy.then(() => expect(verifyCalls).to.eq(2));
	});
});
