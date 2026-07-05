#!/bin/bash
# CI helper: bench + frappe + test-site bootstrap for one matrix cell.
#
# Pattern: hrms .github/helper/install.sh + frappe core's .github/actions/setup
# durability tweaks (see design/ci-plan.md §6). Shared by the server-tests and
# ui-tests jobs; parameterized via environment:
#
#   FRAPPE_BRANCH  frappe branch/tag to clone (default: develop)
#   BUILD_ASSETS   "yes" → run `bench build` in the background (UI-test leg);
#                  anything else skips assets (server-test leg)
#
# The app under test is the checked-out repo at $GITHUB_WORKSPACE (repo root IS
# the frappe app; package/app name: passkeys). Expects a MariaDB service
# container on 127.0.0.1:3306 with root password "root".

set -e

cd ~ || exit

echo "::group::apt dependencies"
sudo apt-get -qq update
sudo apt-get -qq -y remove mysql-server mysql-client || true
sudo apt-get -qq -y install libcups2-dev redis-server mariadb-client libmariadb-dev
# wkhtmltopdf deliberately skipped: no PDF/print tests in this app (ci-plan.md §6)
echo "::endgroup::"

# bench setup requirements / bench build need yarn
command -v yarn >/dev/null 2>&1 || sudo npm install -g yarn

pip install frappe-bench

frappe_branch="${FRAPPE_BRANCH:-develop}"

echo "::group::bench init (frappe ${frappe_branch})"
git clone https://github.com/frappe/frappe --branch "$frappe_branch" --depth 1
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

echo "::group::get-app + requirements (the real resolver test per cell — ci-plan.md §8)"
bench get-app passkeys "${GITHUB_WORKSPACE}"
bench setup requirements --dev
echo "::endgroup::"

if [ "${BUILD_ASSETS:-no}" = "yes" ]; then
  CI=Yes bench build &> ~/frappe-bench/build_assets.log &
  build_pid=$!
fi

bench start &>> ~/frappe-bench/bench_start.log &

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
