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
const SLOW_ECHO = "/api/method/passkeys.tests.ui_test_helpers.slow_guest_echo";

// Browser-context helpers, mirroring sid_reseed_race.cy.js: the straggler must
// ride the BROWSER's jar (it simulates a page XHR still in flight), and the
// login must land its Set-Cookie in the browser jar at response time.
const page_login = () =>
	cy
		.window({ log: false })
		.then((win) =>
			win
				.fetch("/api/method/login", {
					method: "POST",
					credentials: "include",
					headers: { "Content-Type": "application/json", Accept: "application/json" },
					body: JSON.stringify({ usr: USER, pwd: PW() }),
				})
				.then((res) => res.status)
		)
		.then((status) => {
			expect(status, "browser-native login").to.eq(200);
		});

const fire_straggler = () =>
	cy.window({ log: false }).then((win) => {
		win.__wipe_straggler = win.fetch(SLOW_ECHO, { credentials: "include" }).then(
			(res) => ({ ok: true, status: res.status }),
			(err) => ({ ok: false, err: String(err) })
		);
	});

const await_straggler = () =>
	cy
		.window({ log: false })
		.then({ timeout: 10000 }, (win) => win.__wipe_straggler)
		.then((outcome) => {
			expect(outcome, JSON.stringify(outcome)).to.include({ ok: true, status: 200 });
		});

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

	it("an in-flight authenticated straggler cannot resurrect the wiped store", () => {
		// The frappe-v15 CI failure mechanism (reproduced raw with curl):
		// core's delete_session removes the sid's last_db_session_update
		// marker, and v15's Session.update gates its whole write block (DB
		// update + cache hset) on that marker — so a request that loaded its
		// session BEFORE the wipe re-seeds the cache when it lands AFTER it,
		// and cache-first resolution resurrects the sid. The wipe re-seeds the
		// marker AND sweeps the whole cache hash; this pins both
		// deterministically: slow_guest_echo sleeps ~1.5s server-side, far
		// longer than the wipe round-trips, so the ordering is fixed, not
		// load-dependent. The substrate assertion is jar-free on purpose —
		// cache_purged on a SECOND wipe counts exactly the sessions that
		// (re)appeared since the first, so a resurrect cannot hide behind
		// lazy cookie-jar sync.
		cy.visit_login();
		page_login(); // session A, minted in the browser jar
		// A quiet authed portal page — the desk's session-expired handler
		// navigates on post-clear 403 polls and would abort the straggler
		// (same rationale as sid_reseed_race.cy.js).
		cy.visit("/me");
		cy.location("pathname").should("eq", "/me");
		fire_straggler(); // rides sid A; sleeps server-side while we wipe
		cy.clearCookies({ log: false });
		cy.clear_all_test_sessions(); // completes while the straggler sleeps
		await_straggler(); // its session write-back (if any) has now landed
		cy.clear_all_test_sessions().then((message) => {
			expect(
				message.cache_purged,
				"sessions that re-appeared in the cache after the previous wipe"
			).to.eq(0);
		});
		cy.visit("/login");
		cy.location("pathname").should("eq", "/login");
		cy.get("#login_email").should("be.visible");
	});
});
