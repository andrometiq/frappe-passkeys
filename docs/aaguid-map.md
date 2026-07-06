# AAGUID provider map — vendored snapshot

`passkeys/public/aaguid-map.json` maps authenticator AAGUIDs to human provider
names ("Apple Passwords", "Google Password Manager", "YubiKey 5 Series", …).
It powers two display surfaces and nothing else:

- the provider name on management cards (served to the browser at
  `/assets/passkeys/aaguid-map.json`; the server also resolves it into the
  `provider` field of `list_credentials`), and
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
key (both loaders skip underscore-prefixed keys).

Current snapshot: upstream commit `d587293f8ff9c8d57ff63fcf444da0e1e1728e5f`
(2026-07-01, "from MDS file version 264"), 371 entries.

## The strip transform

Upstream entries carry base64 `icon_light` / `icon_dark` SVG blobs (~6.8 MB
total). Neither the cards nor the server use icons, so the vendored file keeps
only the name per AAGUID — a flat `{ "<lowercase-aaguid>": "<name>" }` object
(~28 KB) plus the `_meta` provenance block. Keys are lowercased and sorted for
stable diffs; entries without a name are dropped.

## Refreshing the snapshot (each app release)

From the repo root:

```bash
curl -sL -o /tmp/combined_aaguid.json \
  https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/combined_aaguid.json

python3 - <<'EOF'
import json, urllib.request

with open("/tmp/combined_aaguid.json") as f:
	src = json.load(f)
lean = {}
for key, value in src.items():
	name = (value.get("name") or "").strip()
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
file's shape (lowercase-UUID keys, non-empty string names); the server tests
assert known/unknown lookups still resolve correctly.

Upstream regenerates monthly from the MDS, so refreshing once per app release
is the intended cadence — a stale snapshot only means a new authenticator shows
"Unknown provider" until the next release.
