// Copyright (c) 2026, Frappe Passkeys Contributors
// License: MIT. See LICENSE
//
// App-local Cypress config (DESIGN-v1 §12.3/§12.4). `bench run-ui-tests passkeys`
// does `os.chdir(<app base>)` and runs Cypress from here, so the app ships its
// own config + `cypress/` tree.
// Mirrors frappe's own `cypress.config.js`, minus coverage/split. baseUrl and
// adminPassword are overridden by CYPRESS_baseUrl / CYPRESS_adminPassword that
// bench exports at launch.

const { defineConfig } = require("cypress");

module.exports = defineConfig({
	adminPassword: "admin",
	defaultCommandTimeout: 20000,
	// Cold, dev-mode desk loads (unminified assets + first-visit download) can
	// exceed a tight page-load budget; give the initial /app visit room so the
	// specs don't flake on asset download time.
	pageLoadTimeout: 60000,
	viewportHeight: 960,
	viewportWidth: 1400,
	retries: { runMode: 1, openMode: 0 },
	e2e: {
		setupNodeEvents(on, config) {
			on("before:browser:launch", (browser, launchOptions) => {
				if (browser.family === "chromium") {
					launchOptions.args.push("--disable-dev-shm-usage");
					launchOptions.args.push("--disable-gpu");
					launchOptions.args.push("--no-sandbox");
					// WebAuthn needs a secure context. Chrome trusts localhost /
					// *.localhost / 127.0.0.1 over plain http; any other CI site
					// name (e.g. test_site) is not trustworthy → PublicKeyCredential
					// is absent. Push the fallbacks for those hosts so the specs run
					// regardless of the site name CI injects (NOTES.md §8).
					try {
						const u = new URL(config.baseUrl);
						const host = u.hostname;
						const trusted =
							host === "localhost" ||
							host.endsWith(".localhost") ||
							host === "127.0.0.1";
						if (u.protocol === "http:" && !trusted) {
							launchOptions.args.push(
								`--unsafely-treat-insecure-origin-as-secure=${u.origin}`
							);
							launchOptions.args.push(`--host-resolver-rules=MAP ${host} 127.0.0.1`);
						}
					} catch (e) {
						/* malformed baseUrl — leave args as-is */
					}
				}
				return launchOptions;
			});
			return config;
		},
		testIsolation: false,
		baseUrl: "http://passkeys.localhost:8000",
		specPattern: ["./cypress/integration/*.cy.js"],
		supportFile: "./cypress/support/e2e.js",
	},
});
