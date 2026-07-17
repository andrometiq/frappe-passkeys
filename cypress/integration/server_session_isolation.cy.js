// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Deterministic regression contract for the SERVER-SESSION half of the login
// flake (the other half — cookie-level sid re-seeds — is pinned by
// sid_reseed_race.cy.js). Cypress test isolation clears the CLIENT jar, but
// server-side session rows survive between tests and specs, and /login decides
// its redirect against the SERVER store (login.py: `if session.user !=
// "Guest"`). Stacked cy.login calls (register_passkey's re-login) orphan
// sessions no client-side logout can end; when any layer of the lazily-synced
// cookie jar re-presents such a sid, /login 302s to the authenticated desk and
// the login form never renders — the passkey_a11y CI signature. These tests
// prove clear_all_test_sessions makes every such sid inert, with no load
// injection or timing games: a dead sid is dead on the first try or the fix is
// broken.

const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";

describe("server session isolation", () => {
	before(() => {
		// Return the shared-IP guest ceremony budget this spec's /login visits
		// consume, so suite-order neighbours never inherit a drained window.
		cy.login(USER, PW());
		cy.call("passkeys.tests.ui_test_helpers.clear_guest_ceremony_rate_limit");
	});

	after(() => {
		cy.clearCookies();
	});

	it("a stale authenticated sid is inert after the wipe", () => {
		// Two stacked logins mirror the register_passkey shape: the first
		// session is orphaned in the server store the moment the second mints.
		cy.login(USER, PW());
		cy.login(USER, PW());
		cy.getCookie("sid").then((sid) => {
			expect(sid && sid.value, "authenticated sid in the jar").to.exist;
			expect(sid.value, "authenticated sid in the jar").to.not.eq("Guest");
			cy.clear_all_test_sessions();
			// Re-present the stale sid EXACTLY as a lazily-synced browser jar
			// would after an incomplete clear — the CI failure mode.
			cy.setCookie("sid", sid.value);
			cy.visit("/login");
			cy.location("pathname").should("eq", "/login");
			cy.get("#login_email").should("be.visible");
		});
	});

	it("visit_login renders the login form despite orphaned sessions", () => {
		// End-to-end through the real choke point every login spec uses.
		cy.login(USER, PW());
		cy.login(USER, PW());
		cy.visit_login();
		cy.get("#login_email").should("be.visible");
	});
});
