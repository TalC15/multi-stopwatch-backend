import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { connect } from './support/subscriptionDatabase.js';
import { ids, schema } from './support/database.js';

const name = 'phase8_keeptimer_test';
const cluster = `keeptimer_disposable_${'b'.repeat(32)}`;
// Execute the actual setup body without registering/running its destructive race tests.
// pg.Client is mocked below: these guard tests NEVER open a socket.
for (const file of ['concurrency.test.js', 'shared-concurrency.test.js']) {
  const source = await readFile(new URL(file, import.meta.url), 'utf8');
  const setupSource = source.match(/async function setup\(t\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(setupSource, `${file}: setup boundary must remain reviewable`);
  for (const scenario of ['query-host', 'query-database', 'cluster', 'inventory', 'role', 'valid']) {
    test(`Phase 8 legacy DB guard: ${file} ${scenario}`, async t => {
      const previous = process.env.SUBSCRIPTION_TEST_CLUSTER_NAME;
      process.env.SUBSCRIPTION_TEST_CLUSTER_NAME = cluster;
      t.after(() => { if (previous === undefined) delete process.env.SUBSCRIPTION_TEST_CLUSTER_NAME; else process.env.SUBSCRIPTION_TEST_CLUSTER_NAME = previous; });
      const sql = [], configs = [];
      t.mock.method(pg, 'Client', function(config) {
        configs.push(config);
        return {
          connect: async () => {}, end: async () => {},
          query: async statement => {
            sql.push(statement);
            if (statement.includes('pg_catalog.current_database()')) return {rows:[{database_name:name,server_address:'127.0.0.1',cluster_name:scenario==='cluster'?'other':cluster}]};
            if (statement.includes('pg_catalog.pg_database')) return {rows:['template0','template1','postgres',name,...(scenario==='inventory'?['production']:[])].map(datname=>({datname}))};
            if (statement.includes('pg_catalog.pg_roles')) return {rows:['anon','authenticated','service_role'].map(rolname=>({rolname,rolbypassrls:rolname==='service_role',rolsuper:scenario==='role',rolcanlogin:false}))};
            return {rows:[],rowCount:0};
          },
        };
      });
      const suffix = scenario==='query-host'?'?host=remote.invalid':scenario==='query-database'?'?dbname=production':'';
      const url = `postgres://127.0.0.1:55432/${name}${suffix}`;
      const setup = new Function('pg','connect','url','approved','assert','ids','schema','readFile',
        `${setupSource.replaceAll('import.meta.url', JSON.stringify(import.meta.url))}; return setup;`)(pg,connect,url,name,assert,ids,schema,async()=> '-- fixture migration');
      if (scenario === 'valid') {
        await setup(t);
        assert.equal(configs.length,3);
        assert.ok(configs.every(c=>c.host==='127.0.0.1' && !Object.hasOwn(c,'connectionString')));
        assert.ok(sql.findIndex(s=>s.startsWith('DROP SCHEMA')) >= 9, 'all three connections must pass all preflights');
        assert.ok(!sql.some(s=>/\b(?:CREATE|ALTER|DROP)\s+ROLE\b/.test(s)));
      } else {
        await assert.rejects(()=>setup(t), /query or fragment|mismatch|isolated cluster|pre-provisioned/);
        assert.ok(sql.every(s=>/^SELECT\b/.test(s.trim())), 'no DDL or writes before verified identity');
        if (scenario.startsWith('query')) assert.equal(configs.length,0);
      }
    });
  }
}
