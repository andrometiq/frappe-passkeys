// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Cypress support entry: load app-local commands. Browser exceptions retain
// Cypress's fail-fast default so application regressions cannot become green.

require("./commands");

// Frappe aborts some in-flight page requests during login/logout navigation by
// rejecting their promise with a NON-Error value: the literal `undefined`, or an
// event/object whose toString is `[object Object]` / `[object Event]`. Cypress wraps
// that non-attributable reason in a synthetic "An unknown error has occurred: <reason>"
// error — the exact reason token varies with what Frappe rejected with (seen as both
// `undefined` and `[object Object]` across CI). Ignore only that framework teardown
// signal, matched by its non-attributable reason forms; every attributable
// application exception (a real message, a passkeys Error/DOMException) still fails.
Cypress.on("uncaught:exception", (error) => {
	const message = String((error && error.message) || "");
	const stack = String((error && error.stack) || "");
	if (
		error &&
		/An unknown error has occurred: (undefined|null|\[object [A-Za-z]+\])/.test(message)
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
