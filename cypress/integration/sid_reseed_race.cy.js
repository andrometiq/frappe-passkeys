// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Regression contract for the sid re-seed race (see passkeys/cookie_determinism.py).
//
// Frappe re-issues `Set-Cookie: sid` on every response, so the browser's auth
// state is whatever response happened to arrive LAST — not what the test last
// did. On loaded CI runners this flaked two ways: a straggler authenticated
// response resurrected a client-cleared login before a /login visit
// (passkey_a11y landed on the desk), and a straggler Guest response downgraded
// a freshly-minted session (passkey_second_factor asserted as Guest). These
// tests pin both directions deterministically: `slow_guest_echo` guarantees a
// response that lands ~1.5s after the auth transition, no slow runner
// required. Both fail without the passkeys_deterministic_test_cookies hook
// and pass with it.
//
// Two determinism rules, both learned the hard way while writing this spec:
// - No navigation between firing and awaiting a straggler — navigation aborts
//   the in-flight fetch (the desk does this to itself: after a cookie clear
//   its background polls 403 and its session-expired handler navigates).
// - Every cookie in the contract flows through the BROWSER's network stack
//   (in-page fetch, cy.visit, cy.clearCookies) — never cy.request. Cypress
//   syncs its own jar with the browser's lazily, so mixing the two makes the
//   final-writer order nondeterministic, and the whole point here is that the
//   last response to arrive wins.

const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const SLOW_ECHO = "/api/method/passkeys.tests.ui_test_helpers.slow_guest_echo";

// Fire the straggler from the page context so it carries the browser's
// current cookie jar — exactly like the desk/login-page XHRs that raced on CI.
const fire_straggler = () =>
	cy.window({ log: false }).then((win) => {
		win.__sid_straggler = win.fetch(SLOW_ECHO, { credentials: "include" }).then(
			(res) => ({ ok: true, status: res.status }),
			(err) => ({ ok: false, err: String(err) })
		);
	});

// Explicitly wait for the straggler's response to land (and its Set-Cookie,
// if any, to be processed) before asserting — the race then deterministically
// runs in the direction that exposes the bug instead of being a coin flip.
const await_straggler = () =>
	cy
		.window({ log: false })
		.then({ timeout: 10000 }, (win) => win.__sid_straggler)
		.then((outcome) => {
			expect(outcome, JSON.stringify(outcome)).to.include({ ok: true, status: 200 });
		});

// Browser-native login: the Set-Cookie lands in the browser jar at response
// time, giving the straggler a fixed arrival order to race against.
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

// Browser-native whoami: sends exactly what the browser jar holds.
const page_whoami = () =>
	cy.window({ log: false }).then((win) =>
		win
			.fetch("/api/method/frappe.auth.get_logged_user", { credentials: "include" })
			.then((res) => res.json().then((body) => ({ status: res.status, user: body.message })))
	);

describe("sid re-seed race", () => {
	after(() => {
		cy.clearCookies();
	});

	it("a straggler Guest response cannot downgrade a freshly-minted session", () => {
		cy.visit_login();
		fire_straggler(); // sent as Guest from the login page
		page_login(); // mints a fresh sid in the browser jar (~0.3s)
		await_straggler(); // the Guest response lands AFTER the login (~1.5s)
		// Without the hook the straggler re-seeded sid=Guest over the fresh
		// session and the browser now asks as Guest — the second_factor CI
		// failure (its post-2FA assert went out with `cookie: sid=Guest`).
		page_whoami().then((who) => {
			expect(who, JSON.stringify(who)).to.include({ status: 200, user: USER });
		});
	});

	it("a straggler authenticated response cannot resurrect a cleared login", () => {
		// Session A, established in the browser jar itself.
		cy.visit_login();
		page_login();
		// A quiet portal page, not the desk: the desk's background polls 403
		// after the cookie clear below and its session-expired handler then
		// navigates to /login, aborting the in-flight straggler (verified —
		// that abort race made a desk-based version of this test flaky). The
		// CI races fired from whatever page a before() hook left loaded; the
		// contract only needs A straggler, so fire it from a page that will
		// leave it alive.
		cy.visit("/me");
		cy.location("pathname").should("eq", "/me"); // proves the jar carried A
		fire_straggler(); // carries A — like the before()-page XHRs still in flight on CI
		cy.clearCookies(); // client-side isolation reset; A stays valid server-side
		await_straggler(); // A's response lands after the clear
		// Without the hook the jar now holds still-valid A and /login 301s back
		// to the authenticated desk — the passkey_a11y CI failure. Deliberately
		// a plain cy.visit: visit_login's server_logout would end A and mask
		// the regression this spec exists to pin.
		cy.visit("/login");
		cy.get("#login_email").should("exist");
	});
});
