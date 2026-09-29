# WORKLOG — what was done, when

Append-only, oldest first. Never read this file whole, never edit an entry, never insert above
the last one. Add one entry per unit of work at the bottom:
`## YYYY-MM-DD — <short summary>`, detail below.
Read: `sed -n 1,12p WORKLOG.md; grep '^## ' WORKLOG.md | tail -5`, then only the last entry.
Resume: pick up the last entry's "Next:" and append a new entry when it's done.
This repo is public: entries are publishable summaries; private detail stays in the gitignored
`local-notes/`.

---

## 2026-09-29 — Housekeeping and marketplace listing status
- Agent files tidied: AGENTS.md 163 -> 148 lines (duplicated rules merged, the import-gate path
  made exact, the docs rules folded into Working Rules); CLAUDE.md (a one-line `@AGENTS.md`
  pointer) removed, since agents read AGENTS.md directly; this WORKLOG started. Verbatim
  copies of the pre-cut files are in `archive/2026-09-29/`. In the gitignored local archive,
  two old instruction files got `.txt` copies and the stale `CLAUDE.md` there was removed.
- Release state: v15.0.3 / v16.0.3 released 2026-09-27 (version-15 `ebf4576`, version-16
  `4c0f890`); develop `cca28eb` (docs-site theme; product page vs explainer links separated).
- Frappe Cloud marketplace: listing PR frappe/marketplace#28 is open, awaiting a maintainer
  merge. The listing audit needs all five links (website, support, documentation, privacy
  policy, terms of service) to resolve; the privacy-policy target is still to be chosen.
Next: choose the privacy-policy link for the marketplace listing; once #28 merges, confirm
https://cloud.frappe.io/marketplace/apps/passkeys returns 200. Trimming the gitignored local
context file is deferred to a later pass; its open items stay in that file until they move to
a gitignored open-items note.
