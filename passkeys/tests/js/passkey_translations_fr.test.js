// passkey_translations_fr.test.js — shape and coverage of translations/fr.csv.

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const M = require("../../public/js/passkey_manage_common.bundle.js");

// RFC 4180 rows: quoted fields, "" escapes a quote, newline ends a row.
function parseCsv(text) {
	const rows = [];
	let row = [], field = "", quoted = false;
	for (let i = 0; i < text.length; i++) {
		const ch = text[i];
		if (quoted) {
			if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; }
			else if (ch === '"') quoted = false;
			else field += ch;
		} else if (ch === '"') quoted = true;
		else if (ch === ",") { row.push(field); field = ""; }
		else if (ch === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
		else field += ch;
	}
	if (field || row.length) { row.push(field); rows.push(row); }
	return rows;
}

const rows = parseCsv(fs.readFileSync(path.join(__dirname, "../../translations/fr.csv"), "utf8"));
const catalog = new Map(rows.map((r) => [r[0], r[1]]));
const placeholders = (s) => (s.match(/\{\d+\}|<[^>]+>/g) || []).sort();

test("fr.csv rows are source,translation pairs with unique, non-empty sources", () => {
	assert.ok(rows.length > 0);
	for (const r of rows) {
		assert.strictEqual(r.length, 2, JSON.stringify(r));
		assert.ok(r[0] && r[1], JSON.stringify(r));
	}
	assert.strictEqual(catalog.size, rows.length, "duplicate source strings");
});

test("fr.csv translations keep every placeholder and tag of their source", () => {
	for (const [source, translation] of catalog) {
		assert.deepStrictEqual(placeholders(translation), placeholders(source), source);
	}
});

test("every management COPY string has a French translation", () => {
	const missing = Object.values(M.COPY).filter((s) => !catalog.has(s));
	assert.deepStrictEqual(missing, []);
});
