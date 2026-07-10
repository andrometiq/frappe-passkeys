// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// P3 spec 6 — retry contract (DESIGN-v1 §3.1 step 1, §5.2.10). An assertion is
// NEVER re-POSTed: a `CeremonyExpired` on verify_login must be recovered by a
// fresh begin_login + a fresh gesture, not by replaying the stale signed
// assertion. This spec injects one CeremonyExpired at verify time and asserts the
// bundle (a) issues a second begin_login (re-arm) and (b) lands a session — while
// never sending the same signed assertion to verify_login twice.

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

chromium_only("passkey login retry contract", () => {
	before(() => {
		cy.enable_virtual_authenticator();
		cy.login(USER, PW());
		cy.visit_desk(USER);
		cy.setup_passkey_settings();
		cy.purge_server_passkeys(USER);
		cy.register_passkey(USER, PW());
	});

	after(() => {
		cy.login(USER, PW());
		cy.purge_server_passkeys(USER);
		cy.disable_virtual_authenticator();
		cy.clearCookies();
	});

	it("re-begins on ceremony_expired without ever re-POSTing the assertion", () => {
		const begins = [];
		const verify_payloads = [];
		cy.intercept("POST", "**/passkeys.passkey.begin_login", (req) => {
			begins.push(Date.now());
		}).as("begin");
		let verify_calls = 0;
		cy.intercept_frappe_method("passkeys.passkey.verify_login", "verify", (req, body) => {
			verify_calls += 1;
			try {
				verify_payloads.push(
					typeof body.credential === "string" ? body.credential : JSON.stringify(body.credential)
				);
			} catch (e) {
				verify_payloads.push(null);
			}
			if (verify_calls === 1) {
				// first verify: force the typed transient failure
				req.reply({
					statusCode: 401,
					body: { exc_type: "CeremonyExpired", exception: "CeremonyExpired" },
				});
			}
			// subsequent verifies fall through to the real server
		});

		cy.stub_post_login_shell();
		cy.visit_login_without_conditional();
		cy.get("#passkey-login-btn").click();
		cy.wait("@verify", { timeout: 20000 });
		cy.wait("@verify", { timeout: 20000 });

		cy.location("pathname", { timeout: 25000 }).should("match", /^\/(app|desk)/);
		cy.assert_logged_user(USER);

		cy.then(() => {
			expect(begins.length, "re-begin issued after ceremony_expired").to.be.greaterThan(1);
			expect(verify_calls, "a second verify happened").to.be.greaterThan(1);
			// the same assertion is never replayed to verify_login
			const nonNull = verify_payloads.filter(Boolean);
			expect(nonNull.length, "captured every verify payload").to.eq(verify_calls);
			expect(new Set(nonNull).size, "each verify used a fresh assertion").to.eq(nonNull.length);
		});
	});
});
