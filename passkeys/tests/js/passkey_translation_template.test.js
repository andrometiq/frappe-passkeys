// passkey_translation_template.test.js: every table string the bundles translate by key is in
// the translation template. A table value without N_() never reaches main.pot.
// Runs WITHOUT the bench:  node --test passkeys/tests/js

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const C = require("../../public/js/passkey_common.bundle.js");
const M = require("../../public/js/passkey_manage_common.bundle.js");
const { rpAlertDecision } = require("../../public/js/passkey_site_alert.bundle.js");

const REGENERATE =
	"Mark table strings with N_(), then regenerate passkeys/locale/main.pot from the bench root with " +
	"`bench generate-pot-file --app passkeys`, or, when the bench links apps/passkeys to a checkout " +
	"elsewhere, `env/bin/python apps/passkeys/scripts/generate_pot.py` (CONTRIBUTING.md, Translations).";

// Babel writes each msgid on one line (no wrapping), PO-escaped like a JSON string.
const TEMPLATE = new Set(
	fs.readFileSync(path.join(__dirname, "../../locale/main.pot"), "utf8")
		.split("\n")
		.filter((line) => line.startsWith('msgid "'))
		.map((line) => JSON.parse(line.slice("msgid ".length)))
		.filter(Boolean),
);

function assertInTemplate(strings) {
	assert.ok(strings.length > 0);
	const missing = strings.filter((text) => !TEMPLATE.has(text));
	assert.deepStrictEqual(missing, [], `Strings missing from main.pot. ${REGENERATE}`);
}

test("every manage_common COPY string is in the template", () => {
	assertInTemplate(Object.values(M.COPY));
});

test("every login status, ceremony error and confirmation label is in the template", () => {
	const names = ["NotAllowedError", "AbortError", "InvalidStateError", "SecurityError",
		"NotSupportedError", "ConstraintError", "UnknownError", "TypeError"];
	assertInTemplate([
		...Object.values(C.LOGIN_STATES).map((state) => state.text).filter(Boolean),
		...names.map((name) => C.mapDomException({ name: name }).messageKey),
		C.CEREMONY_EXPIRED_MESSAGE,
		C.confirmationActionContext("passkeys.manage").label,
		C.confirmationActionContext("passkeys.set_passkey_only_login").label,
		C.confirmationActionContext("").label,
	]);
});

test("every site alert message and action is in the template", () => {
	const base = { site_host: "new.example", rp_id: "old.example", working_origins: ["https://old.example"] };
	const decisions = [
		{ reason: "no_rp_id" },
		{ reason: "no_valid_origins" },
		{ reason: "host_outside_rp", status: "off" },
		{ reason: "host_outside_rp", status: "app_only" },
		{ reason: "host_outside_rp", status: "web_works" },
	].map((alert) => rpAlertDecision({ ...base, ...alert }));
	assertInTemplate(decisions.flatMap((decision) => [decision.message, decision.action]));
});
