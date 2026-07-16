#!/bin/bash
# CI helper: bench + frappe + test-site bootstrap for one matrix cell.
#
# Pattern: hrms .github/helper/install.sh + frappe core's .github/actions/setup
# durability tweaks. Shared by the server-tests and
# ui-tests jobs; parameterized via environment:
#
#   FRAPPE_REF     exact frappe commit, tag, or branch to fetch (default: develop)
#   BUILD_ASSETS   "yes" → run `bench build` in the background (UI-test leg);
#                  anything else skips assets (server-test leg)
#
# The app under test is the checked-out repo at $GITHUB_WORKSPACE (repo root IS
# the frappe app; package/app name: passkeys). Expects a MariaDB service
# container on 127.0.0.1:3306 with root password "root".

set -euo pipefail

cd ~ || exit

echo "::group::apt dependencies"
sudo apt-get -qq update
sudo apt-get -qq -y remove mysql-server mysql-client || true
sudo apt-get -qq -y install libcups2-dev redis-server mariadb-client libmariadb-dev
# wkhtmltopdf deliberately skipped: no PDF/print tests in this app
echo "::endgroup::"

# bench setup requirements / bench build need Yarn Classic. Keep the bootstrap
# deterministic instead of accepting the runner image's version or npm's moving
# ``latest`` tag.
if ! command -v yarn >/dev/null 2>&1 || [ "$(yarn --version)" != "1.22.22" ]; then
	sudo npm install -g yarn@1.22.22
fi

python -m pip install "frappe-bench==5.31.0"

frappe_ref="${FRAPPE_REF:-develop}"

echo "::group::resolve frappe (${frappe_ref})"
test ! -e ~/frappe
git init --quiet ~/frappe
git -C ~/frappe remote add origin https://github.com/frappe/frappe.git
git -C ~/frappe fetch --quiet --depth 1 origin "$frappe_ref"
git -C ~/frappe checkout --quiet --detach FETCH_HEAD
frappe_sha="$(git -C ~/frappe rev-parse HEAD)"
echo "Resolved frappe ${frappe_ref} -> ${frappe_sha}"
echo "::endgroup::"

echo "::group::bench init (frappe ${frappe_sha})"
test ! -e ~/frappe-bench
bench init --skip-assets --frappe-path ~/frappe --python "$(which python)" frappe-bench
echo "::endgroup::"

# Charset + CI-speed durability tweaks (frappe .github/actions/setup pattern;
# the DB is disposable — don't pay for fsync)
mariadb --host 127.0.0.1 --port 3306 -u root -proot -e "
  SET GLOBAL character_set_server = 'utf8mb4';
  SET GLOBAL collation_server = 'utf8mb4_unicode_ci';
  SET GLOBAL innodb_flush_log_at_trx_commit = 0;
  SET GLOBAL sync_binlog = 0;"

cd ~/frappe-bench || exit

# Trim Procfile for CI: no watcher, no scheduler (hrms pattern)
sed -i '/^watch:/d;/^schedule:/d' Procfile

echo "::group::get-app + requirements (the real resolver test per cell)"
bench get-app passkeys "${GITHUB_WORKSPACE}"
bench setup requirements --dev
echo "::endgroup::"

if [ "${BUILD_ASSETS:-no}" = "yes" ]; then
  CI=Yes bench build &> ~/frappe-bench/build_assets.log &
  build_pid=$!
fi

bench start &>> ~/frappe-bench/bench_start.log &
bench_pid=$!
echo "$bench_pid" > ~/frappe-bench/bench_start.pid

echo "::group::new-site + install-app"
# --mariadb-user-host-login-scope=% : the site DB user must accept connections
# from the docker bridge (the MariaDB service container is not localhost to it)
bench new-site test_site \
  --db-host 127.0.0.1 \
  --db-root-password root \
  --admin-password admin \
  --mariadb-user-host-login-scope='%' \
  --verbose

bench --site test_site set-config allow_tests 1 --parse
bench --site test_site set-config host_name "http://test_site:8000"

bench --site test_site install-app passkeys
echo "::endgroup::"

if [ -n "${build_pid:-}" ]; then
  if ! wait "$build_pid"; then
    echo "Asset build failed:"
    cat ~/frappe-bench/build_assets.log
    exit 1
	fi
fi

if ! kill -0 "$bench_pid" 2>/dev/null; then
	echo "Bench exited during setup:"
	cat ~/frappe-bench/bench_start.log
	exit 1
fi

{
	echo "### Runtime provenance"
	echo
	echo "- Frappe ref: \`${frappe_ref}\`"
	echo "- Frappe commit: \`${frappe_sha}\`"
	echo "- Python: \`$(python --version 2>&1)\`"
	echo "- Node: \`$(node --version)\`"
	echo "- Bench: \`$(bench --version)\`"
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
