# AAGUID provider map — vendored snapshot

`passkeys/public/aaguid-map.json` maps authenticator AAGUIDs to human provider
names ("Apple Passwords", "Google Password Manager", "YubiKey 5 Series", …).
It powers two display surfaces and nothing else:

- the provider name on management cards (served to the browser at
  `/assets/passkeys/aaguid-map.json`; the server also resolves it into the
  `provider` field of `list_credentials`). Desk requests the file with the
  app version as a query string (`?v=16.0.9`), so after an app update the
  browser fetches the new snapshot instead of an asset it cached, and
- the default label a new credential gets when the user doesn't name it.

**Display only, never policy.** An AAGUID is authenticator-asserted and — under
`attestation="none"` — unverified. A zero, empty, or unmapped AAGUID is a
normal state (Safari ships all zeros): cards show "Unknown provider", default
labels fall back to "Device passkey" / "Passkey", nothing errors. An empty or
missing snapshot degrades the same way, so a failed refresh can never break
login or management.

## Source and license

The snapshot is `combined_aaguid.json` from the community
[passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids)
repository (MIT license) — the maintainers' curated passkey-provider list
merged with the FIDO Alliance Metadata Service (MDS) entries for security
keys. Attribution and upstream provenance also ride in the file's own `_meta`
key (the server loader skips underscore-prefixed keys; the client only reads string or `name` values, so `_meta` never resolves either).

Current snapshot: upstream commit `cd4f847a6144acb2281e6b7bd98326e3bac3fdc7`
(2026-11-15, "from MDS file version 301"), 417 entries.

## The strip transform

Upstream entries carry base64 `icon_light` / `icon_dark` SVG blobs (~6.8 MB
total). Neither the cards nor the server use icons, so the vendored file keeps
only the name per AAGUID — a flat `{ "<lowercase-aaguid>": "<name>" }` object
(~28 KB) plus the `_meta` provenance block. Keys are lowercased and sorted for
stable diffs; entries without a name are dropped.

A name is display text, not a description. The transform cuts everything from the
first `http://` or `https://` on, with the punctuation before it, and cuts a name
still longer than 120 characters at the last whole word, ending it with "…". Some
upstream entries are a sentence with a product link; they become the product name.

## Refreshing the snapshot (each app release)

`.github/helper/aaguid_freshness.sh` fails while upstream has a change that this snapshot has
lacked for more than 30 days. The release steps in `CONTRIBUTING.md` run it before the release
branches are pushed, and their CI (`version-15`, `version-16`) runs it again. Nothing checks between
releases. From the repo root:

```bash
curl -sL -o /tmp/combined_aaguid.json \
  https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/combined_aaguid.json

python3 - <<'EOF'
import json, re, urllib.request

MAX_NAME = 120


def display_name(raw):
	name = raw.strip()
	url = re.search(r"https?://", name)
	if url:
		name = name[: url.start()].rstrip(" .,;:-")
	if len(name) > MAX_NAME:
		name = name[: MAX_NAME - 1].rsplit(" ", 1)[0].rstrip(" .,;:-") + "…"
	return name


with open("/tmp/combined_aaguid.json") as f:
	src = json.load(f)
lean = {}
for key, value in src.items():
	name = display_name(value.get("name") or "")
	if name:
		lean[key.lower()] = name

with urllib.request.urlopen(
	"https://api.github.com/repos/passkeydeveloper/passkey-authenticator-aaguids/commits?path=combined_aaguid.json&per_page=1"
) as resp:
	head = json.load(resp)[0]

out = {
	"_meta": {
		"source": "https://github.com/passkeydeveloper/passkey-authenticator-aaguids (combined_aaguid.json)",
		"license": "MIT (upstream repository license)",
		"upstream_ref": head["sha"],
		"upstream_date": head["commit"]["committer"]["date"][:10],
		"entries": len(lean),
		"refresh": "see docs/aaguid-map.md",
	}
}
out.update(dict(sorted(lean.items())))
with open("passkeys/public/aaguid-map.json", "w") as f:
	json.dump(out, f, indent=1, ensure_ascii=False)
	f.write("\n")
print(f"wrote {len(lean)} entries")
EOF
```

Then update the "Current snapshot" line above with the new `upstream_ref` /
date / entry count, eyeball the diff (names only — no icons, no URLs, nothing
that isn't a product name), and run the test suites. The node test asserts the
file's shape (lowercase-UUID keys, non-empty string names, every name within the
rule above); the server tests assert known/unknown lookups still resolve correctly.

Upstream regenerates monthly from the MDS, so refreshing once per app release
is the intended cadence — a stale snapshot only means a new authenticator shows
"Unknown provider" until the next release.
