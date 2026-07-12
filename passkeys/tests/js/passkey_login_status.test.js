// passkey_login_status.test.js — pure unit tests for the VISIBLE login-status state
// machine in passkey_common.js: the copy/tone table (one source of truth feeding both
// the on-page element and the aria-live region), the legal staged transitions, and the
// browser-gesture-error → state mapping. Runs WITHOUT the bench and WITHOUT jsdom:
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");
const C = require("../../public/js/passkey_common.js");

// ---------------------------------------------------------- copy/tone table

test("loginStatusView: every state maps to copy + tone; unknown ⇒ idle", () => {
	assert.strictEqual(C.loginStatusView("idle").visible, false);
	assert.strictEqual(C.loginStatusView("idle").text, "");
	assert.strictEqual(C.loginStatusView("waiting").tone, "progress");
	assert.strictEqual(C.loginStatusView("waiting").text, "Waiting for your device…");
	assert.strictEqual(C.loginStatusView("verifying").tone, "progress");
	assert.strictEqual(C.loginStatusView("verifying").text, "Verifying your signature…");
	assert.strictEqual(C.loginStatusView("verifying_slow").tone, "progress");
	assert.match(C.loginStatusView("verifying_slow").text, /slow connection/);
	assert.strictEqual(C.loginStatusView("success").tone, "success");
	assert.strictEqual(C.loginStatusView("success").terminal, true);
	assert.strictEqual(C.loginStatusView("success").text, "You're in — taking you through…");
	assert.strictEqual(C.loginStatusView("cancelled").tone, "error");
	assert.strictEqual(C.loginStatusView("failed").tone, "error");
	// unknown name falls back to the idle view object
	assert.strictEqual(C.loginStatusView("does-not-exist"), C.loginStatusView("idle"));
});

test("every error state names a route out (no dead-ends, no humor)", () => {
	["cancelled", "unsupported", "failed"].forEach((s) => {
		const v = C.loginStatusView(s);
		assert.strictEqual(v.tone, "error");
		assert.match(v.text, /passkey|password|another way|sign in/i, s + " must offer a way out");
	});
});

// ---------------------------------------------------------- staged transitions

test("staged happy path: idle → waiting → verifying → verifying_slow → success", () => {
	const m = new C.LoginStatus();
	assert.strictEqual(m.state, "idle");
	assert.strictEqual(m.to("waiting").text, "Waiting for your device…");
	assert.strictEqual(m.to("verifying").text, "Verifying your signature…");
	assert.strictEqual(m.to("verifying_slow").tone, "progress");
	assert.strictEqual(m.to("success").text, "You're in — taking you through…");
	assert.strictEqual(m.state, "success");
});

test("conditional/autofill path enters verifying straight from idle (no waiting beat)", () => {
	const m = new C.LoginStatus();
	assert.strictEqual(m.can("verifying"), true);
	assert.strictEqual(m.to("verifying").tone, "progress");
	assert.strictEqual(m.state, "verifying");
});

test("success is terminal: a late error can never overwrite the resolved beat", () => {
	const m = new C.LoginStatus({ state: "success" });
	assert.strictEqual(m.can("failed"), false);
	assert.strictEqual(m.to("failed").text, "You're in — taking you through…"); // unchanged
	assert.strictEqual(m.state, "success");
});

test("illegal jumps are safe no-ops (stay put, return the current view)", () => {
	const m = new C.LoginStatus();
	// idle can't jump straight to success (must pass through waiting/verifying)
	assert.strictEqual(m.can("success"), false);
	assert.strictEqual(m.to("success").visible, false); // still idle
	assert.strictEqual(m.state, "idle");
});

test("a visible failure persists until the next attempt (failure → waiting or verifying)", () => {
	const m = new C.LoginStatus({ state: "verifying" });
	m.to("failed");
	assert.strictEqual(m.state, "failed");
	assert.strictEqual(m.can("waiting"), true); // explicit-button retry
	assert.strictEqual(m.can("verifying"), true); // conditional retry
});

test("verifying → waiting is allowed (transparent ceremony_expired re-arm on the button)", () => {
	const m = new C.LoginStatus({ state: "verifying" });
	assert.strictEqual(m.can("waiting"), true);
	assert.strictEqual(m.to("waiting").text, "Waiting for your device…");
});

test("strict:false is an escape hatch that lets any transition through", () => {
	const m = new C.LoginStatus({ strict: false });
	m.to("success");
	assert.strictEqual(m.state, "success");
	m.to("waiting"); // would be illegal under strict mode
	assert.strictEqual(m.state, "waiting");
});

// ------------------------------------------------ browser-error → state mapping

test("A5: the removed/stale-passkey state is distinct, error-toned, and doesn't assert the account fact", () => {
	const v = C.loginStatusView("removed");
	assert.strictEqual(v.tone, "error");
	assert.strictEqual(v.visible, true);
	assert.match(v.text, /didn't work here/);
	assert.match(v.text, /may have been removed/);
	// midway rule: must NOT assert enrolment ("isn't registered"/"unknown")
	assert.doesNotMatch(v.text, /registered|unknown|not enrolled/i);
	// it is NOT the same copy as the generic failure
	assert.notStrictEqual(v.text, C.loginStatusView("failed").text);
});

test("removed is reachable mid-ceremony and re-arms back to the form", () => {
	const m = new C.LoginStatus({ state: "verifying" });
	assert.strictEqual(m.can("removed"), true);
	assert.strictEqual(m.to("removed").text, C.loginStatusView("removed").text);
	assert.strictEqual(m.can("waiting"), true); // returns the user to the login form
	assert.strictEqual(m.can("verifying"), true);
});

test("loginStatusForServerKind: unknown_credential ⇒ removed; every other typed refusal ⇒ failed", () => {
	assert.strictEqual(C.loginStatusForServerKind("unknown_credential"), "removed");
	assert.strictEqual(C.loginStatusForServerKind("ceremony_expired"), "failed");
	assert.strictEqual(C.loginStatusForServerKind("confirmation_required"), "failed");
	assert.strictEqual(C.loginStatusForServerKind("unknown"), "failed");
});

test("loginStatusForDomCode: cancel + timeout collapse to cancelled; unsupported stays distinct", () => {
	// cancel and timeout are BOTH NotAllowedError → user_cancelled → cancelled (honest collapse)
	assert.strictEqual(C.loginStatusForDomCode("user_cancelled"), "cancelled");
	assert.strictEqual(C.loginStatusForDomCode("no_credentials"), "cancelled");
	assert.strictEqual(C.loginStatusForDomCode("not_supported"), "unsupported");
	assert.strictEqual(C.loginStatusForDomCode("network"), "failed");
	assert.strictEqual(C.loginStatusForDomCode("confirmation_failed"), "failed");
	assert.strictEqual(C.loginStatusForDomCode("anything-else"), "failed");
});
