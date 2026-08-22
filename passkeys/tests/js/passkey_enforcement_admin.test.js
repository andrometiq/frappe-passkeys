// passkey_enforcement_admin.test.js — pure view-model for the User-form Passkeys
// section's admin enforcement-recovery controls (one-click exemption + grace reset).
//
// No bench / no DOM: these exercise the framework-light pure functions in
// passkey_manage_common.bundle.js (shouldShowEnforcementAdmin, enforcementAdminViewModel)
// exactly like the sibling nudge/enforcement view-model tests.
//
//   node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");

const M = require("../../public/js/passkey_manage_common.bundle.js");

test("shouldShowEnforcementAdmin only on an enforcement rung", () => {
	assert.equal(M.shouldShowEnforcementAdmin({ enforcement: { policy: "Enforce" } }), true);
	assert.equal(M.shouldShowEnforcementAdmin({ enforcement: { policy: "Enforce After Date" } }), true);
	assert.equal(M.shouldShowEnforcementAdmin({ enforcement: { policy: "Nudge" } }), false);
	assert.equal(M.shouldShowEnforcementAdmin({ enforcement: { policy: "Off" } }), false);
	assert.equal(M.shouldShowEnforcementAdmin({}), false);
	assert.equal(M.shouldShowEnforcementAdmin(null), false);
});

test("enforcementAdminViewModel: in-scope, no passkey, grace spent", () => {
	const vm = M.enforcementAdminViewModel({
		exempt: false, in_scope: true,
		credential_count: 0, grace_used: 2, grace_total: 3, grace_remaining: 1,
	});
	assert.equal(vm.exempt, false);
	assert.equal(vm.exemptButtonKey, "enforceAdminExempt"); // offers to exempt
	assert.equal(vm.exemptButtonPrimary, true);
	assert.equal(vm.nextExemptValue, true);
	assert.equal(vm.resetDisabled, false); // grace was spent → reset is live
	assert.deepEqual(vm.indicator, { color: "orange", textKey: "enforceAdminStateEnforced" });
});

test("enforcementAdminViewModel: exempt user flips the button + indicator", () => {
	const vm = M.enforcementAdminViewModel({
		exempt: true, in_scope: false,
		credential_count: 0, grace_used: 0, grace_total: 3, grace_remaining: 3,
	});
	assert.equal(vm.exemptButtonKey, "enforceAdminUnexempt"); // offers to remove exemption
	assert.equal(vm.exemptButtonPrimary, false);
	assert.equal(vm.nextExemptValue, false);
	assert.equal(vm.resetDisabled, true); // nothing spent → reset disabled
	assert.equal(vm.indicator.color, "green");
	assert.equal(vm.indicator.textKey, "enforceAdminStateExempt");
});

test("enforcementAdminViewModel: in scope but already enrolled reads as satisfied", () => {
	const vm = M.enforcementAdminViewModel({
		exempt: false, in_scope: true,
		credential_count: 2, grace_used: 0, grace_total: 3, grace_remaining: 3,
	});
	assert.deepEqual(vm.indicator, { color: "green", textKey: "enforceAdminStateSatisfied" });
});

test("enforcementAdminViewModel: out-of-scope user reads as not-in-scope", () => {
	const vm = M.enforcementAdminViewModel({
		exempt: false, in_scope: false,
		credential_count: 0, grace_used: 0, grace_total: 3, grace_remaining: 3,
	});
	assert.deepEqual(vm.indicator, { color: "gray", textKey: "enforceAdminStateNotScope" });
});

test("enforcementAdminViewModel coerces string/absent numerics", () => {
	const vm = M.enforcementAdminViewModel({ exempt: false, in_scope: true, grace_used: "2", grace_total: "3" });
	assert.equal(vm.graceUsed, 2);
	assert.equal(vm.graceTotal, 3);
	assert.equal(vm.resetDisabled, false);
});
