// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// Cypress support entry (mirrors frappe/cypress/support/e2e.js): load the
// custom commands and swallow uncaught app exceptions so an unrelated Desk
// script error never fails a passkey spec.

import "./commands";

Cypress.on("uncaught:exception", () => false);
