// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Action-confirmation Cypress suites (happy path, accessibility, call() retry,
// concurrency, error taxonomy, grant semantics), merged into one file. Each
// nested describe keeps its OWN before/after via cy.confirm_setup() /
// cy.confirm_teardown(), so every suite runs against a freshly reset virtual
// authenticator (no cross-suite state coupling).

const chromium_only = Cypress.isBrowser({ family: "chromium" }) ? describe : describe.skip;
const USER = "Administrator";
const PW = () => Cypress.env("adminPassword") || "admin";
const PROBE = "passkeys.tests.ui_test_helpers.confirm_probe";
const PROBE_FAIL = "passkeys.tests.ui_test_helpers.confirm_probe_failing";
const ACTION = "passkeys.tests.confirm_probe";

// Raw POST to a @passkey_protected method with a grant header, via fetch — which
// always settles on ANY HTTP status. The grant-semantics specs deliberately hit
// error responses (the action throws, or the burned grant is refused); frappe.call
// can leave its promise unsettled on such a 4xx, hanging the spec for the full
// cy.wrap timeout (the A-F20 flake). fetch resolves with the response object, so the
// specs read the HTTP outcome (ok / status) directly — the bundle's own post() does
// the same for exactly this reason.
const grantedPost = (win, method, token, grant) =>
	win.fetch("/api/method/" + method, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"X-Frappe-CSRF-Token": win.frappe.csrf_token || "",
			"X-Passkey-Grant": grant,
		},
		credentials: "same-origin",
		body: JSON.stringify({ token: token }),
	});

chromium_only("passkey action-confirmation", () => {
	describe("happy path", () => {
		before(() => cy.confirm_setup());

		after(() => cy.confirm_teardown());

		it("confirm(action, params) resolves a grant token that authorizes the action", () => {
			cy.login(USER, PW());
			cy.visit_desk(USER);
			cy.window().its("frappe.passkeys").should("exist");
			cy.window().then((win) => {
				const p = win.frappe.passkeys.confirm(ACTION, { token: "T1" });
				cy.get(".passkey-confirm-passkey").should("be.visible").click();
				return cy.wrap(p, { timeout: 20000 }).then((grant) => {
					expect(grant, "grant token").to.be.a("string").and.have.length.greaterThan(10);
					return cy
						.wrap(
							win.frappe.call({
								method: PROBE,
								args: { token: "T1" },
								headers: { "X-Passkey-Grant": grant },
							})
						)
						.then((r) => {
							expect(r.message.confirmed).to.eq(true);
							expect(r.message.token).to.eq("T1");
						});
				});
			});
		});
	});

	describe("accessibility", () => {
		before(() => cy.confirm_setup());

		after(() => cy.confirm_teardown());

		it("is a labelled modal dialog, Esc-cancels, and returns focus to the opener", () => {
			cy.login(USER, PW());
			cy.visit_desk(USER);
			cy.hold_passkey_taps(); // keep the ceremony pending → the dialog stays open
			cy.window().then((win) => {
				// an invoking control that owns focus before the dialog opens
				win.document.body.insertAdjacentHTML(
					"beforeend",
					'<button id="confirm-opener">go</button>'
				);
				win.document.getElementById("confirm-opener").focus();
				win.__confirm_reject = null;
				win.frappe.passkeys
					.confirm(ACTION, { token: "A1" })
					.catch((err) => (win.__confirm_reject = err));
			});

			cy.get(".modal.show").should(($modal) => {
				const modal = $modal[0];
				expect(modal.getAttribute("role"), "modal role").to.eq("dialog");
				expect(modal.querySelector(".passkey-confirm"), "passkey confirm body").to.exist;
				const title = modal.querySelector(".modal-title");
				expect(title && title.textContent.trim(), "dialog title").to.not.eq("");
			});
			cy.get(".modal.show .passkey-confirm-msg").should("have.attr", "aria-live", "polite");

			cy.focused().type("{esc}");
			cy.get(".modal.show").should("not.exist");
			cy.get(".passkey-confirm").should("not.be.visible");
			cy.focused().should("have.id", "confirm-opener");
			cy.window().its("__confirm_reject.code").should("eq", "user_cancelled");
			cy.simulate_passkey_tap();
		});
	});

	describe("call() retry", () => {
		before(() => cy.confirm_setup());

		after(() => cy.confirm_teardown());

		it("retries once with the grant header and echoes the fingerprint verbatim", () => {
			cy.login(USER, PW());
			cy.visit_desk(USER);
			cy.intercept("POST", "**/passkeys.confirm.begin_confirmation").as("begin");
			cy.window().then((win) => {
				const p = win.frappe.passkeys.call(PROBE, { token: "R1" });
				cy.get(".passkey-confirm-passkey").should("be.visible").click();
				return cy.wrap(p, { timeout: 20000 }).then((message) => {
					expect(message.confirmed).to.eq(true);
					expect(message.token).to.eq("R1");
				});
			});
			cy.wait("@begin").then(({ request }) => {
				// the retry sent the server's fingerprint verbatim, never raw params.
				expect(request.body).to.have.property("payload_hash");
				expect(request.body).to.not.have.property("params");
			});
		});
	});

	describe("concurrency", () => {
		before(() => cy.confirm_setup());

		after(() => cy.confirm_teardown());

		it("two identical concurrent call()s share one ceremony but only one single-use grant", () => {
			cy.login(USER, PW());
			cy.visit_desk(USER);
			let begins = 0;
			cy.intercept("POST", "**/passkeys.confirm.begin_confirmation", (req) => {
				begins += 1;
				req.continue();
			});
			cy.window().then((win) => {
				const args = { token: "C1" };
				win.__passkey_confirm_results = Promise.allSettled([
					win.frappe.passkeys.call(PROBE, args),
					win.frappe.passkeys.call(PROBE, args),
				]);
			});
			cy.get(".modal.show").should("be.visible");
			cy.get(".passkey-confirm-passkey").should("be.visible").click();
			cy.window().then((win) =>
				cy.wrap(win.__passkey_confirm_results, { timeout: 20000 }).then((results) => {
					const fulfilled = results.filter((r) => r.status === "fulfilled");
					const rejected = results.filter((r) => r.status === "rejected");
					expect(fulfilled, "one retried action uses the grant").to.have.length(1);
					expect(rejected, "the second retry cannot reuse the grant").to.have.length(1);
					expect(fulfilled[0].value.confirmed).to.eq(true);
					expect(rejected[0].reason.code).to.eq("confirmation_failed");
					expect(begins, "one shared begin_confirmation").to.eq(1);
				})
			);
			cy.get(".modal.show", { timeout: 10000 }).should("not.exist");
			cy.get(".passkey-confirm").should("not.be.visible");
		});
	});

	describe("error taxonomy", () => {
		const reject_code = (win, promise) =>
			promise.then(
				() => {
					throw new Error("expected rejection");
				},
				(err) => err && err.code
			);

		before(() => cy.confirm_setup());

		after(() => cy.confirm_teardown());

		it("maps a cancelled OS sheet to user_cancelled", () => {
			cy.login(USER, PW());
			cy.visit_desk(USER);
			cy.window().then((win) => {
				const err = new Error("cancelled");
				err.name = "NotAllowedError";
				cy.stub(win.navigator.credentials, "get").rejects(err);
				win.__passkey_confirm_reject = reject_code(
					win,
					win.frappe.passkeys.confirm(ACTION, { token: "E1" })
				);
			});
			cy.get(".passkey-confirm-passkey").should("be.visible").click();
			cy.window().then((win) =>
				cy.wrap(win.__passkey_confirm_reject, { timeout: 20000 }).should("eq", "user_cancelled")
			);
		});

		it("maps an offline transport failure to network", () => {
			cy.login(USER, PW());
			cy.visit_desk(USER);
			cy.intercept("POST", "**/passkeys.confirm.begin_confirmation", { forceNetworkError: true });
			cy.window().then((win) =>
				cy
					.wrap(reject_code(win, win.frappe.passkeys.confirm(ACTION, { token: "E2" })), {
						timeout: 20000,
					})
					.should("eq", "network")
			);
		});
	});

	describe("grant semantics", () => {
		before(() => cy.confirm_setup());

		after(() => cy.confirm_teardown());

		it("a consumed grant is rejected on replay (single-use)", () => {
			cy.login(USER, PW());
			cy.visit_desk(USER);
			cy.window().then((win) => {
				win.__gs = {};
				win.frappe.passkeys
					.confirm(ACTION, { token: "G1" })
					.then((g) => (win.__gs.grant = g), (e) => (win.__gs.err = (e && e.code) || "err"));
			});
			cy.get(".passkey-confirm-passkey").should("be.visible").click();
			// Poll the grant off the window instead of cy.wrap()-ing a cross-realm promise.
			cy.window().its("__gs.grant", { timeout: 20000 }).should("be.a", "string");
			cy.window().then((win) => {
				// a valid grant authorizes the action once
				grantedPost(win, PROBE, "G1", win.__gs.grant).then((r) =>
					r.json().then((b) => (win.__gs.first = { ok: r.ok, confirmed: !!(b && b.message && b.message.confirmed) }))
				);
			});
			cy.window().its("__gs.first.ok", { timeout: 20000 }).should("eq", true);
			cy.window().its("__gs.first.confirmed").should("eq", true);
			cy.window().then((win) => {
				// replay the same grant → refused server-side (single-use: it was burned)
				grantedPost(win, PROBE, "G1", win.__gs.grant).then(
					(r) => (win.__gs.replay = r.ok ? "ACCEPTED" : "REJECTED"),
					() => (win.__gs.replay = "neterr")
				);
			});
			cy.window().its("__gs.replay", { timeout: 20000 }).should("eq", "REJECTED");
		});

		it("burns the grant even when the wrapped action fails (A-F20)", () => {
			cy.login(USER, PW());
			cy.visit_desk(USER);
			cy.window().then((win) => {
				win.__gs = {};
				win.frappe.passkeys
					.confirm(PROBE_FAIL, { token: "G2" })
					.then((g) => (win.__gs.grant = g), (e) => (win.__gs.err = (e && e.code) || "err"));
			});
			cy.get(".passkey-confirm-passkey").should("be.visible").click();
			cy.window().its("__gs.grant", { timeout: 20000 }).should("be.a", "string");
			cy.window().then((win) => {
				// the action throws AFTER the grant is consumed → the gesture is spent
				grantedPost(win, PROBE_FAIL, "G2", win.__gs.grant).then(
					(r) => (win.__gs.first = r.ok ? "ACCEPTED" : "FAILED"),
					() => (win.__gs.first = "neterr")
				);
			});
			cy.window().its("__gs.first", { timeout: 20000 }).should("eq", "FAILED");
			cy.window().then((win) => {
				// the same grant no longer authorizes a retry — it was burned
				grantedPost(win, PROBE_FAIL, "G2", win.__gs.grant).then(
					(r) => (win.__gs.replay = r.ok ? "ACCEPTED" : "REJECTED"),
					() => (win.__gs.replay = "neterr")
				);
			});
			cy.window().its("__gs.replay", { timeout: 20000 }).should("eq", "REJECTED");
		});
	});
});
