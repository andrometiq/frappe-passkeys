#!/bin/bash
# Exercise the real Frappe app lifecycle on a site isolated from the server suite.

set -euo pipefail

bench_dir="${BENCH_DIR:-/home/runner/frappe-bench}"
site="${LIFECYCLE_SITE:-lifecycle_site}"
export_path="$bench_dir/sites/$site/private/files/passkeys-lifecycle-export.json"

cd "$bench_dir"

echo "::group::create clean lifecycle site"
bench new-site "$site" \
	--db-host 127.0.0.1 \
	--db-root-password root \
	--admin-password admin \
	--mariadb-user-host-login-scope='%' \
	--verbose
bench --site "$site" set-config allow_tests 1 --parse
# Credential exports are authenticated with the site's encryption key. Some
# minimal new-site environments do not create one until an encrypted feature is
# first used, so make this deployment prerequisite explicit in the lifecycle gate.
encryption_key="$("$bench_dir/env/bin/python" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
# `--` ends click option parsing: Fernet keys are urlsafe base64, so ~1/64 of
# them start with `-` and would otherwise be parsed as an option cluster
# ("Error: No such option: -R"), randomly failing the run.
bench --site "$site" set-config encryption_key -- "$encryption_key"
unset encryption_key
echo "::endgroup::"

echo "::group::install + migrate"
bench --site "$site" install-app passkeys
bench --site "$site" migrate
bench --site "$site" execute passkeys.tests.lifecycle_helpers.seed_lifecycle_data
bench --site "$site" execute passkeys.install.export_credentials \
	--kwargs "{\"path\": \"$export_path\"}"
test -s "$export_path"
# The export must capture passkey_only_login=1, but production intentionally
# blocks uninstall until the live lockout flag is cleared.
bench --site "$site" execute passkeys.tests.lifecycle_helpers.prepare_lifecycle_uninstall
echo "::endgroup::"

echo "::group::uninstall + reinstall + migrate"
bench --site "$site" uninstall-app passkeys --yes --no-backup
tables="$(bench --site "$site" mariadb --skip-column-names --execute "show tables")"
if [[ "$tables" == *"tabWebAuthn Credential"* || "$tables" == *"tabWebAuthn User Handle"* ]]; then
	echo "Passkey tables survived uninstall" >&2
	exit 1
fi
# A false-success uninstall is caught here: install-app refuses an app that is
# still registered on the site.
bench --site "$site" install-app passkeys
bench --site "$site" migrate
bench --site "$site" execute passkeys.tests.lifecycle_helpers.configure_lifecycle_mode
bench --site "$site" execute passkeys.install.import_credentials \
	--kwargs "{\"path\": \"$export_path\"}"
bench --site "$site" execute passkeys.tests.lifecycle_helpers.assert_lifecycle_data_restored
echo "::endgroup::"

echo "Lifecycle gate OK: install -> seed/export -> uninstall -> reinstall -> import/verify"
