// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Password → passkey second factor. Four
// journeys against the real committed bundle + a CDP virtual authenticator:
//   1. password submit → the passkey sheet opens by itself → session, with no click on
//      "Use a passkey" (dispatch, not stacked onto OTP);
//   2. when the browser refuses that automatic sheet, the dialog stays as it was, with no
//      error, and the OTP-fallback secondary action hands off to core's own OTP UI
//      (`#login_token`) when passkey_2fa_allow_otp_fallback is on;
//   3. a failed leg-2 verify re-arms the UI and a second gesture succeeds WITHOUT
//      ever re-POSTing an assertion (fresh server re-arm is covered
//      by passkeys/tests/test_second_factor.py).
//   4. a non-401 server failure clears the pending state so a fresh gesture works.
//   5. with passkey sign-in also on, the pending autofill request is aborted first, so the
//      browser lets the second-factor request through.
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
		cy.clear_guest_ceremony_rate_limit(); // clean IP ceremony budget for this spec (still admin)
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

	function submitPassword(options = {}, { autofill = false } = {}) {
		cy.intercept_frappe_method("passkeys.passkey.begin_login", "begin_login");
		cy.intercept_frappe_method("passkeys.passkey.login_with_password", "login_with_password");
		cy.visit_login(options);
		cy.wait("@begin_login", { timeout: 15000 }).then(({ response }) => {
			const body = response && response.body;
			const config = (body && (body.message || body)) || {};
			expect(config.enabled, "passkey login bundle is enabled").to.eq(true);
			expect(config.modes && config.modes.second_factor, "second-factor mode reached the browser").to.eq(
				true
			);
			if (autofill) expect(config.modes.first_factor, "passkey sign-in mode reached the browser").to.eq(true);
		});
		cy.get("html", { timeout: 15000 }).should(
			"have.attr",
			"data-passkeys-second-factor-ready",
			"true"
		);
		if (autofill) {
			cy.window().its("frappe._passkey_login._state.conditionalAbort").should("not.be.null");
		}
		cy.get("#login_email").clear().type(SF_USER);
		cy.get("#login_password").clear().type(SF_PW, { log: false });
		cy.get(".form-login:visible")
			.find("button[type='submit']")
			.then(($button) => $button[0].click());
		cy.wait("@login_with_password", { timeout: 15000 }).then(({ response }) => {
			expect(response && response.statusCode, JSON.stringify(response && response.body)).to.eq(200);
		});
	}

	it("password submit opens the passkey sheet by itself and mints a session", () => {
		cy.intercept_frappe_method("passkeys.passkey.verify_second_factor", "verify_sf");
		submitPassword();
		// No click on "Use a passkey": the virtual authenticator answers the automatic sheet.
		cy.wait("@verify_sf", { timeout: 20000 }).its("response.statusCode").should("eq", 200);
		cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk|me)/);
		cy.assert_logged_user(SF_USER);
	});

	it("keeps the dialog silent when the browser refuses the automatic sheet, and the OTP fallback completes sign-in", () => {
		let fallbackTmpId;
		cy.intercept_frappe_method("passkeys.passkey.fallback_to_otp", "fallback_otp");
		cy.intercept_frappe_method("login", "core_otp", (req, body) => {
			expect(body).to.have.property("otp");
			expect(body.tmp_id).to.eq(fallbackTmpId);
			expect(body).not.to.have.property("usr");
		});
		// The browser refuses the sheet opened without a click (Safari can, after the password
		// request), as it would a dismissed one.
		submitPassword({
			onBeforeLoad(win) {
				win.__passkey_sf_gets = 0;
				Object.defineProperty(win.navigator.credentials, "get", {
					configurable: true,
					value() {
						win.__passkey_sf_gets += 1;
						return Promise.reject(new win.DOMException("refused", "NotAllowedError"));
					},
				});
			},
		});
		cy.window().its("__passkey_sf_gets").should("eq", 1);
		cy.get(".passkey-dialog").should("be.visible");
		cy.get(".passkey-dialog .passkey-dialog-error").should("have.text", "");
		cy.contains(".passkey-dialog button", "Use a passkey").should("be.visible").and("not.be.disabled");
		// the secondary action exists only because passkey_2fa_allow_otp_fallback
		// is on AND the user is OTP-capable (server-gated).
		cy.contains(".passkey-dialog button", "Use a verification code instead").click();
		// core's own OTP form paints its token input — the passkey app got out of
		// the way (dispatch to core's leg 2, no stacking).
		cy.get("#login_token", { timeout: 15000 }).should("be.visible");
		cy.wait("@fallback_otp").then(({ response }) => {
			expect(response.statusCode).to.eq(200);
			fallbackTmpId = response.body.tmp_id;
			// Read as admin, then restore the guest cookies before core's OTP submission.
			cy.getCookies({ log: false }).then((cookies) => {
				cy.login("Administrator", ADMIN_PW());
				cy.call("passkeys.tests.ui_test_helpers.get_otp_code", { tmp_id: response.body.tmp_id })
					.then((body) => {
						cy.clearCookies({ log: false });
						cookies.forEach(({ name, value, domain, path, secure, httpOnly, sameSite }) =>
							cy.setCookie(name, value, { domain, path, secure, httpOnly, sameSite, log: false })
						);
						cy.get("#login_token").type(body.message, { log: false });
					});
			});
		});
		cy.get("#verify_token").click();
		cy.wait("@core_otp").then(({ response }) => {
			expect(response.statusCode, JSON.stringify(response.body)).to.eq(200);
		});
		cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk|me)/);
		cy.assert_logged_user(SF_USER);
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
		// The automatic sheet's assertion meets the stubbed re-arm.
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
		cy.wait("@verify_sf", { timeout: 20000 }).its("response.statusCode").should("eq", 500);
		cy.get(".passkey-dialog .passkey-dialog-error", { timeout: 15000 }).should("not.be.empty");
		cy.contains(".passkey-dialog button", "Use a passkey").click();
		cy.wait("@verify_sf", { timeout: 20000 }).its("response.statusCode").should("eq", 200);

		cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk|me)/);
		cy.then(() => expect(verifyCalls).to.eq(2));
	});

	describe("with passkey sign-in also on", () => {
		before(() => {
			cy.login("Administrator", ADMIN_PW());
			cy.visit_desk("Administrator");
			cy.setup_second_factor({ first_factor: true, otp_fallback: true });
			cy.clear_guest_ceremony_rate_limit();
			cy.call("logout");
		});

		it("aborts the autofill request so the second-factor sheet opens by itself and mints a session", () => {
			const gets = [];
			cy.intercept_frappe_method("passkeys.passkey.verify_second_factor", "verify_sf");
			submitPassword({
				onBeforeLoad(win) {
					// The virtual authenticator would answer the autofill request by itself (it holds
					// the user's passkey), so it is held pending here, and another request made while
					// it is open is refused the way Chromium refuses it.
					const credentials = win.navigator.credentials;
					const real_get = credentials.get.bind(credentials);
					let autofill = null;
					Object.defineProperty(credentials, "get", {
						configurable: true,
						value(options) {
							gets.push({ mediation: options.mediation, autofill_open: !!autofill });
							if (options.mediation !== "conditional") {
								if (autofill) {
									return Promise.reject(new win.DOMException("A request is already pending.", "OperationError"));
								}
								return real_get(options);
							}
							return new Promise((resolve, reject) => {
								autofill = options.signal;
								options.signal.addEventListener(
									"abort",
									() => {
										autofill = null;
										reject(new win.DOMException("aborted", "AbortError"));
									},
									{ once: true }
								);
							});
						},
					});
				},
			}, { autofill: true });
			cy.wait("@verify_sf", { timeout: 20000 }).its("response.statusCode").should("eq", 200);
			cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk|me)/);
			cy.assert_logged_user(SF_USER);
			cy.then(() => {
				expect(gets.map((get) => get.mediation)).to.deep.eq(["conditional", undefined]);
				expect(gets[1].autofill_open, "the autofill request was aborted first").to.eq(false);
			});
		});
	});
});
