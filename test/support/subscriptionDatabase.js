import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import pg from 'pg';
import { schema } from './database.js';

export const phase1 = await readFile(new URL('../../db/migrations/20261007_subscription_phase1.sql', import.meta.url), 'utf8');
const previous = await Promise.all([
  '20260925_company_account_deactivation.sql', '20260925_personal_sync_api.sql',
  '20260928_shared_authority.sql',
].map(name => readFile(new URL(`../../db/migrations/${name}`, import.meta.url), 'utf8')));

// Return explicit pg options, NEVER a connectionString to be parsed a second time.
export function localTestUrl(value = process.env.SUBSCRIPTION_TEST_DATABASE_URL) {
  if (!value) return null;
  let url;
  try { url = new URL(value); } catch { throw new Error('Invalid subscription test database URL'); }
  if (!['postgres:', 'postgresql:'].includes(url.protocol) ||
      !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
      !/^\/[a-zA-Z0-9_]+_keeptimer_test$/.test(url.pathname) ||
      url.search !== '' || value.includes('?') || value.includes('#') ||
      /[\u0000-\u0020\u007f]/.test(value) ||
      (url.port !== '' && (!/^\d+$/.test(url.port) || Number(url.port) < 1 || Number(url.port) > 65535))) {
    throw new Error('SUBSCRIPTION_TEST_DATABASE_URL requires loopback TCP, *_keeptimer_test, and no query or fragment');
  }
  let user, password;
  try {
    user = decodeURIComponent(url.username) || 'postgres';
    password = decodeURIComponent(url.password);
  } catch { throw new Error('Invalid subscription test database credentials encoding'); }
  return Object.freeze({
    // Pin localhost to IPv4 loopback; never resolve it through configurable DNS.
    host: url.hostname === '[::1]' ? '::1' : '127.0.0.1',
    port: url.port ? Number(url.port) : 5432,
    database: url.pathname.slice(1), user,
    // A function also prevents an empty password falling back to PGPASSWORD.
    password: () => password,
    ssl: false, options: '-c search_path=public,pg_catalog',
    application_name: 'keeptimer-subscription-tests', connectionTimeoutMillis: 5000,
  });
}

async function verifyServer(db, config, clusterName) {
  const { rows } = await db.query(`SELECT pg_catalog.current_database() AS database_name,
    pg_catalog.host(pg_catalog.inet_server_addr()) AS server_address,
    pg_catalog.current_setting('cluster_name') AS cluster_name`);
  const identity = rows[0];
  // inet_server_addr() is NULL for Unix sockets: deliberately fail closed.
  if (rows.length !== 1 || identity.database_name !== config.database ||
      !['127.0.0.1', '::1'].includes(identity.server_address) ||
      identity.cluster_name !== clusterName) {
    throw new Error('Subscription test server identity/loopback/disposable cluster mismatch; no schema reset');
  }
  const databases = (await db.query('SELECT datname FROM pg_catalog.pg_database')).rows;
  const allowed = new Set(['template0', 'template1', 'postgres', config.database]);
  if (!databases.some(row => row.datname === config.database) ||
      databases.some(row => !allowed.has(row.datname))) {
    throw new Error('Subscription tests require an isolated cluster with no other databases; no schema reset');
  }
  const roles = (await db.query(`SELECT rolname, rolbypassrls, rolsuper, rolcanlogin
    FROM pg_catalog.pg_roles WHERE rolname = ANY($1::text[])`,
  [['anon', 'authenticated', 'service_role']])).rows;
  for (const name of ['anon', 'authenticated', 'service_role']) {
    const role = roles.find(row => row.rolname === name);
    if (!role || role.rolbypassrls !== (name === 'service_role') ||
        role.rolsuper !== false || role.rolcanlogin !== false) {
      throw new Error(`Subscription test role ${name} must be pre-provisioned with expected attributes; no role changes or schema reset`);
    }
  }
}

export async function connect(t) {
  const config = localTestUrl();
  if (!config) throw new Error('SUBSCRIPTION_TEST_DATABASE_URL is required for PostgreSQL connections');
  const clusterName = process.env.SUBSCRIPTION_TEST_CLUSTER_NAME;
  if (!/^keeptimer_disposable_[0-9a-f]{32}$/.test(clusterName || '')) {
    throw new Error('SUBSCRIPTION_TEST_CLUSTER_NAME must identify a freshly provisioned isolated cluster');
  }
  const db = new pg.Client(config);
  try {
    await db.connect();
    await verifyServer(db, config, clusterName);
  } catch (error) {
    await db.end().catch(() => {});
    throw error;
  }
  t.after(() => db.end());
  // Match PGlite's exec for multi-statement migration files.
  db.exec = sql => db.query(sql);
  return db;
}

// Destructive ONLY after URL, server identity, cluster inventory and role checks.
// Run this suite separately from other schema-resetting test files.
export async function database(t, { migrate = true } = {}) {
  const external = Boolean(localTestUrl());
  const db = external ? await connect(t) : new PGlite();
  if (!external) {
    t.after(() => db.close());
    // Only this new, in-memory PGlite instance owns its roles. External clusters
    // must already have the expected roles; never CREATE/ALTER/DROP ROLE there.
    await db.exec('CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role BYPASSRLS');
  }
  await db.exec('DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public');
  await db.exec(schema.replace(/CREATE ROLE (anon|authenticated|service_role);/g, ''));
  // Reconcile the historical fixture with the supplied 2026-10-07 snapshot.
  await db.exec(`
    ALTER TABLE users ALTER COLUMN id SET DEFAULT gen_random_uuid(), ADD COLUMN created_at timestamptz DEFAULT now();
    ALTER TABLE workspaces ALTER COLUMN id SET DEFAULT gen_random_uuid(), ADD COLUMN created_at timestamptz DEFAULT now(),
      ALTER COLUMN shared_mode_enabled DROP NOT NULL, ALTER COLUMN shared_mode_enabled SET DEFAULT false,
      ADD CONSTRAINT workspaces_owner_id_fkey FOREIGN KEY(owner_id) REFERENCES users(id);
    ALTER TABLE sessions ALTER COLUMN id SET DEFAULT gen_random_uuid(), ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(), ADD COLUMN user_agent text;
    ALTER TABLE timers ALTER COLUMN id SET DEFAULT gen_random_uuid(), ADD COLUMN created_at timestamptz DEFAULT now(),
      ALTER COLUMN name SET NOT NULL, ALTER COLUMN type SET NOT NULL,
      ALTER COLUMN status SET DEFAULT 'idle', ALTER COLUMN record_status SET DEFAULT 'active',
      ALTER COLUMN accumulated_ms SET DEFAULT 0, ALTER COLUMN paused_count SET DEFAULT 0, ALTER COLUMN is_pay SET DEFAULT false;
    CREATE INDEX idx_sessions_refresh_hash ON sessions(refresh_token_hash);
    CREATE INDEX idx_sessions_user_id ON sessions(user_id);
  `);
  for (const sql of previous) await db.exec(sql);
  for (const name of ['users', 'workspaces', 'sessions', 'timers', 'keeptimer_shared_scopes']) {
    await db.exec(`ALTER TABLE ${name} ENABLE ROW LEVEL SECURITY`);
  }
  await db.exec(`GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
    GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role;
  `);
  if (migrate) await db.exec(phase1);
  return db;
}

export async function user(db, role = 'worker', extra = {}) {
  const values = { id: randomUUID(), username: randomUUID(), pin_hash: '$2b$12$fixtureHashOnly', role, ...extra };
  const columns = Object.keys(values);
  await db.query(`INSERT INTO users(${columns.join(',')}) VALUES(${columns.map((_, i) => `$${i + 1}`).join(',')})`, Object.values(values));
  return values.id;
}

export async function subscription(db, extra = {}) {
  const owner = extra.user_id || await user(db);
  const values = {
    user_id: owner, plan_code: 'individual', sequence_no: 1,
    starts_at: '2026-10-01T00:00:00Z', ends_at: '2026-11-01T00:00:00Z',
    term_months: 1, amount_minor: 10000, created_by_user_id: owner, ...extra,
  };
  const columns = Object.keys(values);
  return (await db.query(`INSERT INTO subscriptions(${columns.join(',')}) VALUES(${columns.map((_, i) => `$${i + 1}`).join(',')}) RETURNING *`, Object.values(values))).rows[0];
}

export async function asRole(db, role, action) {
  if (!['anon', 'authenticated', 'service_role'].includes(role)) throw new Error('Invalid test role');
  await db.exec(`SET ROLE ${role}`);
  try { return await action(); } finally { await db.exec('RESET ROLE'); }
}
