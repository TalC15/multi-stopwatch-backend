#!/usr/bin/env bash
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true || "${KT_CI_RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  printf '%s\n' 'BLOCKED: use the GitHub-hosted workflow; this script must not run on a personal/self-hosted machine.' >&2
  exit 2
fi
[[ -f package.json && -f test/support/subscriptionDatabase.js ]] || { printf '%s\n' 'Backend repository root required.' >&2; exit 2; }
command -v docker >/dev/null
command -v node >/dev/null
unset TEST_DATABASE_URL SUBSCRIPTION_TEST_DATABASE_URL SUBSCRIPTION_TEST_CLUSTER_NAME PHASE5_DISPOSABLE_DB_APPROVED

kt_nonce="$(node -e "process.stdout.write(require('node:crypto').randomBytes(16).toString('hex'))")"
kt_container_name="keeptimer-ci-${kt_nonce}"
kt_cluster_name="keeptimer_disposable_${kt_nonce}"
kt_database_name=ci_keeptimer_test
kt_port=55432
kt_container_id=''
export POSTGRES_PASSWORD="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))")"
export PGPASSWORD="$POSTGRES_PASSWORD"
printf '::add-mask::%s\n' "$POSTGRES_PASSWORD"

cleanup() {
  local kt_cleanup_status=$?
  trap - EXIT
  # Redact while this shell still owns its ephemeral DB credentials, including
  # failing preflight/tests. Artifact uploads happen in a later Actions step.
  node scripts/ci/sanitize-evidence.mjs || kt_cleanup_status=1
  if [[ -n "$kt_container_id" ]]; then
    # Remove only the exact container created here, including its anonymous volume.
    local kt_found_id
    kt_found_id="$(docker inspect --format '{{.Id}}' "$kt_container_name" 2>/dev/null || true)"
    if [[ "$kt_found_id" == "$kt_container_id" ]]; then
      docker rm --force --volumes "$kt_container_id" >/dev/null 2>&1 || true
    fi
  fi
  exit "$kt_cleanup_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Host networking is intentional: the existing guard checks BOTH ends of the
# connection are loopback. A bridged postgres service would fail that check.
# No host directory, production volume or external connection is mounted.
kt_container_id="$(docker run --detach --name "$kt_container_name" --network host \
  --env POSTGRES_PASSWORD --env POSTGRES_DB="$kt_database_name" \
  postgres:18 -p "$kt_port" -c listen_addresses=127.0.0.1 -c cluster_name="$kt_cluster_name")"

kt_ready=false
for kt_attempt in {1..60}; do
  if docker exec "$kt_container_id" pg_isready -h 127.0.0.1 -p "$kt_port" -U postgres -d "$kt_database_name" >/dev/null 2>&1; then
    kt_ready=true
    break
  fi
  if [[ "$(docker inspect --format '{{.State.Running}}' "$kt_container_id")" != true ]]; then break; fi
  sleep 1
done
if [[ "$kt_ready" != true ]]; then
  printf '%s\n' 'Disposable PostgreSQL did not become ready; tests were not started.' >&2
  docker logs --tail 30 "$kt_container_id" >&2 || true
  exit 1
fi

mkdir -p reports
docker inspect --format '{{.Image}}' "$kt_container_id" > reports/pg18-image.txt
docker exec -e PGPASSWORD -i "$kt_container_id" psql -X -h 127.0.0.1 -p "$kt_port" \
  -U postgres -d "$kt_database_name" -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE anon NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE authenticated NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE service_role NOLOGIN NOSUPERUSER BYPASSRLS;
SQL

export SUBSCRIPTION_TEST_DATABASE_URL="postgresql://postgres:${POSTGRES_PASSWORD}@127.0.0.1:${kt_port}/${kt_database_name}"
export TEST_DATABASE_URL="$SUBSCRIPTION_TEST_DATABASE_URL"
export SUBSCRIPTION_TEST_CLUSTER_NAME="$kt_cluster_name"
export PHASE5_DISPOSABLE_DB_APPROVED="$kt_database_name"
printf '::add-mask::%s\n' "$SUBSCRIPTION_TEST_DATABASE_URL"

# Execute the repository's actual connection/identity/inventory/role guard.
node --input-type=module <<'JS' > reports/pg18-preflight.json
import {connect} from './test/support/subscriptionDatabase.js';
let close;
const db=await connect({after:fn=>{close=fn;}});
try {
  const identity=(await db.query(`SELECT current_database() AS database,
    current_setting('cluster_name') AS cluster_name,
    current_setting('server_version_num')::integer AS version,
    host(inet_server_addr()) AS server_address`)).rows[0];
  if(identity.version<180000 || identity.version>=190000) throw Error('PostgreSQL 18 required');
  console.log(JSON.stringify(identity,null,2));
} finally { await close?.(); }
JS

shopt -s nullglob
kt_test_files=(test/*concurrency.test.js test/*pg18*.test.js)
if (( ${#kt_test_files[@]} == 0 )); then printf '%s\n' 'No concurrency tests found.' >&2; exit 1; fi
printf '%s\n' "${kt_test_files[@]}" > reports/pg18-test-files.txt
node --test --test-concurrency=1 --test-reporter=tap "${kt_test_files[@]}" > reports/pg18.tap 2>&1

# A connection precondition silently turning the job into SKIP must not look green.
node --input-type=module <<'JS'
import {readFile} from 'node:fs/promises';
const tap=await readFile('reports/pg18.tap','utf8');
if(/#\s*SKIP\b/i.test(tap)) throw Error('PG18 suite contained skipped tests; inspect pg18.tap');
if(!/^# tests [1-9]\d*$/m.test(tap)) throw Error('PG18 test evidence is missing');
JS
