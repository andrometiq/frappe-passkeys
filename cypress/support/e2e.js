// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Cypress support entry: load app-local commands. Browser exceptions retain
// Cypress's fail-fast default so application regressions cannot become green.

require("./commands");

// Frappe aborts some in-flight page requests during login/logout navigation by
// rejecting their promise with the literal value `undefined`. Cypress wraps that
// non-Error reason in this exact synthetic error. Ignore only that framework
// teardown signal; every attributable application exception still fails the run.
Cypress.on("uncaught:exception", (error) => {
	const message = String((error && error.message) || "");
	const stack = String((error && error.stack) || "");
	if (
		error &&
		message.includes("An unknown error has occurred: undefined")
	) {
		return false;
	}
	// Frappe Desk can route before its sidebar DOM exists on a cold /app load.
	// Frappe's own Cypress harness suppresses every uncaught exception; keep the
	// exception scoped to this exact core stack so app errors still fail tests.
	if (
		message.includes("Cannot read properties of undefined (reading 'show')") &&
		stack.includes("Sidebar.toggle")
	) {
		return false;
	}
	return true;
});
