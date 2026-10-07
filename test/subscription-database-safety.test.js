import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { connect, database, localTestUrl } from './support/subscriptionDatabase.js';

const databaseName = 'subscription_keeptimer_test';
const clusterName = `keeptimer_disposable_${'a'.repeat(32)}`;
const goodUrl = `postgres://postgres:fixture@127.0.0.1:55432/${databaseName}`;
const PgClient = pg.Client;

function env(t, values) {
  const previous = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });
}

// This harness never opens a socket. It exercises database() through pg.Client,
// including the ordering of verification, connection cleanup and schema reset.
function harness(t, overrides = {}) {
  env(t, { SUBSCRIPTION_TEST_DATABASE_URL: goodUrl, SUBSCRIPTION_TEST_CLUSTER_NAME: clusterName });
  const state = {
    constructed: 0, connected: 0, ended: 0, sql: [], config: null,
    identity: { database_name: databaseName, server_address: '127.0.0.1', cluster_name: clusterName },
    databases: ['template0', 'template1', 'postgres', databaseName].map(datname => ({ datname })),
    roles: ['anon', 'authenticated', 'service_role'].map(rolname => ({
      rolname, rolbypassrls: rolname === 'service_role', rolsuper: false, rolcanlogin: false,
    })),
    ...overrides,
  };
  const client = {
    async connect() { state.connected++; if (state.connectError) throw state.connectError; },
    async end() { state.ended++; },
    async query(sql) {
      state.sql.push(sql);
      if (state.queryError) throw state.queryError;
      if (sql.includes('pg_catalog.current_database()')) return { rows: state.identity ? [state.identity] : [] };
      if (sql.includes('FROM pg_catalog.pg_database')) return { rows: structuredClone(state.databases) };
      if (sql.includes('FROM pg_catalog.pg_roles')) return { rows: structuredClone(state.roles) };
      return { rows: [] };
    },
  };
  t.mock.method(pg, 'Client', function(config) {
    state.constructed++; state.config = config; return client;
  });
  return state;
}

function noWrites(state) {
  assert.ok(state.sql.every(sql => /^SELECT\b/.test(sql.trim())), 'only read-only preflight SQL may run');
  assert.ok(!state.sql.some(sql => /\b(?:DROP|ALTER|CREATE)\s+(?:SCHEMA|ROLE)\b/i.test(sql)));
}

for (const suffix of [
  '?host=remote.example', '?hostaddr=1.2.3.4', '?service=anything',
  '?dbname=production', '?port=5433', '?sslmode=require', '?options=-c%20search_path=evil',
  '?application_name=test', '?', '#fragment', '#',
]) {
  test(`subscription guard: rejects URL suffix ${suffix} before pg.Client/connect or SQL`, async t => {
    const state = harness(t);
    const host = suffix === '?host=remote.example' ? '127.0.0.1' : 'localhost';
    process.env.SUBSCRIPTION_TEST_DATABASE_URL = `postgres://${host}/${databaseName}${suffix}`;
    await assert.rejects(() => database(t), /no query or fragment/);
    assert.equal(state.constructed, 0); assert.equal(state.connected, 0);
    assert.deepEqual(state.sql, []);
  });
}

for (const value of [
  'postgres://remote.example/subscription_keeptimer_test',
  'postgres://127.0.0.1/production',
  'postgres://127.0.0.1/subscription_keeptimer_test/extra',
  'postgres://127.0.0.1/subscription%5fkeeptimer_test',
  'http://localhost/subscription_keeptimer_test',
  'postgres://127.0.0.2/subscription_keeptimer_test',
  'postgres://[::ffff:127.0.0.1]/subscription_keeptimer_test',
  'postgres://%2Ftmp/subscription_keeptimer_test',
  'postgres://localhost:0/subscription_keeptimer_test',
  'postgres://localhost:65536/subscription_keeptimer_test',
  'postgres://localhost/subscription_keeptimer_test\n',
  'host=localhost dbname=subscription_keeptimer_test',
]) {
  test(`subscription guard: rejects unsafe URL ${JSON.stringify(value)} before connect or SQL`, async t => {
    const state = harness(t);
    process.env.SUBSCRIPTION_TEST_DATABASE_URL = value;
    await assert.rejects(() => database(t), /database URL|requires loopback/);
    assert.equal(state.constructed, 0); assert.equal(state.connected, 0);
    assert.deepEqual(state.sql, []);
  });
}

test('subscription guard: malformed credentials encoding rejected without logging credentials or connecting', async t => {
  const state = harness(t);
  process.env.SUBSCRIPTION_TEST_DATABASE_URL = `postgres://user:%zz@localhost/${databaseName}`;
  await assert.rejects(() => database(t), { message: 'Invalid subscription test database credentials encoding' });
  assert.equal(state.connected, 0); assert.deepEqual(state.sql, []);
});

for (const [value, host, port] of [
  [`postgres://localhost/${databaseName}`, '127.0.0.1', 5432],
  [`postgresql://127.0.0.1:55432/${databaseName}`, '127.0.0.1', 55432],
  [`postgres://[::1]:55432/${databaseName}`, '::1', 55432],
]) {
  test(`subscription guard: accepts sanitized loopback config ${host}:${port}`, async t => {
    const state = harness(t);
    process.env.SUBSCRIPTION_TEST_DATABASE_URL = value;
    state.identity.server_address = host;
    await connect(t);
    assert.equal(state.connected, 1);
    assert.equal(state.config.host, host); assert.equal(state.config.port, port);
    assert.equal(state.config.database, databaseName);
    assert.equal(Object.hasOwn(state.config, 'connectionString'), false);
    noWrites(state);
  });
}

test('subscription guard: explicit pg config ignores PGHOST/PGPORT/PGDATABASE/PGOPTIONS and preserves encoded credentials', t => {
  env(t, { PGHOST: 'remote.example', PGPORT: '6000', PGDATABASE: 'production', PGUSER: 'wrong',
    PGPASSWORD: 'wrong', PGOPTIONS: '-c search_path=evil', PGSSLMODE: 'require' });
  const config = localTestUrl(`postgres://fixture%40user:p%3F%23%40%3A@localhost:55432/${databaseName}`);
  const client = new PgClient(config); // Inspect actual driver parsing; never connect.
  assert.equal(client.host, '127.0.0.1'); assert.equal(client.port, 55432);
  assert.equal(client.database, databaseName); assert.equal(client.user, 'fixture@user');
  assert.equal(client.password(), 'p?#@:');
  assert.equal(client.connectionParameters.options, '-c search_path=public,pg_catalog');
  assert.equal(client.connectionParameters.ssl, false);
  const empty = new PgClient(localTestUrl(`postgres://localhost/${databaseName}`));
  assert.equal(empty.password(), ''); assert.equal(empty.user, 'postgres');
});

for (const marker of [undefined, 'true', 'shared-local-cluster']) {
  test(`subscription guard: missing/invalid cluster opt-in ${marker} rejects before connect`, async t => {
    const state = harness(t);
    if (marker === undefined) delete process.env.SUBSCRIPTION_TEST_CLUSTER_NAME;
    else process.env.SUBSCRIPTION_TEST_CLUSTER_NAME = marker;
    await assert.rejects(() => database(t), /freshly provisioned isolated cluster/);
    assert.equal(state.connected, 0); assert.deepEqual(state.sql, []);
  });
}

for (const mismatch of [
  { database_name: 'production' }, { database_name: 'other_keeptimer_test' },
  { server_address: '1.2.3.4' }, { server_address: null }, { server_address: undefined },
  { server_address: '::ffff:127.0.0.1' }, { cluster_name: 'shared' }, { cluster_name: '' },
]) {
  test(`subscription guard: runtime identity ${JSON.stringify(mismatch)} fails BEFORE DROP`, async t => {
    const state = harness(t);
    Object.assign(state.identity, mismatch);
    await assert.rejects(() => database(t), /identity\/loopback\/disposable cluster mismatch/);
    assert.equal(state.connected, 1); assert.equal(state.ended, 1);
    noWrites(state); assert.equal(state.sql.length, 1);
  });
}

test('subscription guard: absent server identity fails closed and closes connection', async t => {
  const state = harness(t, { identity: null });
  await assert.rejects(() => database(t), /identity\/loopback/);
  assert.equal(state.ended, 1); noWrites(state);
});

for (const datname of ['production', 'another_keeptimer_test', 'custom_template']) {
  test(`subscription guard: extra cluster database ${datname} rejected BEFORE DROP`, async t => {
    const state = harness(t);
    state.databases.push({ datname });
    await assert.rejects(() => database(t), /isolated cluster with no other databases/);
    noWrites(state); assert.equal(state.ended, 1);
  });
}

test('subscription guard: missing inventory target fails closed', async t => {
  const state = harness(t, { databases: [] });
  await assert.rejects(() => database(t), /isolated cluster/);
  noWrites(state); assert.equal(state.ended, 1);
});

test('subscription guard: existing service_role NOBYPASSRLS is unchanged; no ALTER ROLE or DROP', async t => {
  const state = harness(t);
  state.roles.find(r => r.rolname === 'service_role').rolbypassrls = false;
  const before = structuredClone(state.roles);
  await assert.rejects(() => database(t), /role service_role must be pre-provisioned/);
  assert.deepEqual(state.roles, before);
  noWrites(state); assert.equal(state.ended, 1);
  assert.ok(!state.sql.some(sql => /ALTER\s+ROLE/i.test(sql)));
});

for (const name of ['anon', 'authenticated', 'service_role']) {
  test(`subscription guard: missing ${name} fails without creating cluster roles or dropping schema`, async t => {
    const state = harness(t);
    state.roles = state.roles.filter(r => r.rolname !== name);
    await assert.rejects(() => database(t), /must be pre-provisioned/);
    noWrites(state); assert.equal(state.ended, 1);
  });
}

for (const [name, attribute] of [['anon', 'rolbypassrls'], ['authenticated', 'rolsuper'], ['service_role', 'rolcanlogin']]) {
  test(`subscription guard: unexpected ${name}.${attribute} is rejected without reconfiguration`, async t => {
    const state = harness(t);
    state.roles.find(r => r.rolname === name)[attribute] = true;
    await assert.rejects(() => database(t), /must be pre-provisioned/);
    noWrites(state);
  });
}

test('subscription guard: correctly provisioned isolated cluster reaches fixture reset only AFTER all checks', async t => {
  const state = harness(t);
  const before = structuredClone(state.roles);
  await database(t, { migrate: false });
  assert.equal(state.constructed, 1); assert.equal(state.connected, 1);
  const reset = state.sql.findIndex(sql => sql.startsWith('DROP SCHEMA'));
  assert.equal(reset, 3, 'identity, inventory, role checks must precede reset');
  assert.match(state.sql[0], /current_database/);
  assert.match(state.sql[1], /pg_database/);
  assert.match(state.sql[2], /pg_roles/);
  assert.ok(!state.sql.some(sql => /\b(?:CREATE|ALTER|DROP)\s+ROLE\b/i.test(sql)));
  assert.deepEqual(state.roles, before);
  assert.ok(state.sql.some(sql => /CREATE TABLE public\.users/.test(sql)), 'fixture initialization continues');
});

for (const errorType of ['connectError', 'queryError']) {
  test(`subscription guard: ${errorType} closes connection without schema changes`, async t => {
    const state = harness(t, { [errorType]: new Error('fixture failure') });
    await assert.rejects(() => database(t), /fixture failure/);
    assert.equal(state.ended, 1); noWrites(state);
  });
}
