import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { readFile } from "node:fs/promises";
import { ids, schema } from "./support/database.js";

// Real PostgreSQL connections are necessary to test row locks; the embedded
// SQL fixture cannot simulate two concurrent transactions. The database must
// be a disposable LOCAL test DB: this test resets its public schema.
const url = process.env.TEST_DATABASE_URL;
const enabled = Boolean(url);

async function setup(t) {
  const parsed = new URL(url);
  if (!(["localhost", "127.0.0.1", "::1"].includes(parsed.hostname) &&
        parsed.pathname.endsWith("_keeptimer_test"))) {
    throw new Error("TEST_DATABASE_URL must point to a disposable LOCAL *_keeptimer_test database");
  }
  const connections = await Promise.all([0, 1, 2].map(async () => {
    const client = new pg.Client({ connectionString: url });
    await client.connect();
    return client;
  }));
  t.after(async () => { await Promise.all(connections.map(c => c.end())); });
  const [admin, writer, closer] = connections;

  await admin.query("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public");
  for (const name of ["anon", "authenticated", "service_role"]) {
    const { rowCount } = await admin.query("SELECT 1 FROM pg_roles WHERE rolname=$1", [name]);
    if (!rowCount) await admin.query(`CREATE ROLE ${name}`);
  }
  await admin.query(schema.replace(/CREATE ROLE (anon|authenticated|service_role);/g, ""));
  await admin.query(await readFile(new URL("../db/migrations/20260925_company_account_deactivation.sql", import.meta.url), "utf8"));
  await admin.query("INSERT INTO workspaces(id,name) VALUES ($1,'A'),($2,'B')", [ids.company, ids.otherCompany]);
  for (const [id, name, role, workspace] of [
    [ids.manager, "manager", "manager", ids.company],
    [ids.worker, "worker", "worker", ids.company],
    [ids.outsider, "outsider", "manager", ids.otherCompany],
    [ids.superadmin, "superadmin", "superadmin", null],
  ]) {
    await admin.query("INSERT INTO users(id,username,pin_hash,role,workspace_id) VALUES($1,$2,'pin',$3,$4)", [id,name,role,workspace]);
  }
  await admin.query("UPDATE workspaces SET owner_id=$1 WHERE id=$2", [ids.manager, ids.company]);
  await closer.query("SET lock_timeout = '250ms'");
  await writer.query("SET lock_timeout = '250ms'");
  return { admin, writer, closer };
}

const closing = (client) => client.query(
  "SELECT public.keeptimer_close_company_worker($1,$2) AS result",
  [ids.manager, ids.worker],
);

const writing = (client, id, updates, actor = ids.worker) => client.query(
  "SELECT public.keeptimer_change_timer($1,$2,$3::jsonb,false)",
  [actor, id, JSON.stringify(updates)],
);

test("login session insert locks worker against closure; late login cannot create a session", { skip: !enabled }, async (t) => {
  const { admin, writer, closer } = await setup(t);
  await writer.query("BEGIN");
  try {
    await writer.query("INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,'hash')", [ids.session, ids.worker]);
    await assert.rejects(() => closing(closer), error => error.code === "55P03");
    await writer.query("COMMIT");
  } catch (err) { await writer.query("ROLLBACK"); throw err; }
  await closing(closer);
  assert.ok((await admin.query("SELECT revoked_at FROM sessions WHERE id=$1", [ids.session])).rows[0].revoked_at);
  await assert.rejects(() => writer.query("INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,'late')", [ids.personal, ids.worker]), /KEEPTIMER_ACCOUNT_DISABLED/);
});

test("in-flight refresh locks worker before session and cannot outlive closure", { skip: !enabled }, async (t) => {
  const { admin, writer, closer } = await setup(t);
  await admin.query("INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,'hash')", [ids.session, ids.worker]);
  const refresh = () => writer.query(
    "SELECT public.keeptimer_refresh_session($1,$2,'hash') AS active",
    [ids.worker, ids.session],
  );
  await writer.query("BEGIN");
  try {
    assert.equal((await refresh()).rows[0].active, true);
    await assert.rejects(() => closing(closer), error => error.code === "55P03");
    await writer.query("COMMIT");
  } catch (err) { await writer.query("ROLLBACK"); throw err; }
  await closing(closer);
  assert.equal((await refresh()).rows[0].active, false);
});

test("personal owner, superadmin personal, and shared writes lock worker before deactivation", { skip: !enabled }, async (t) => {
  const { admin, writer, closer } = await setup(t);
  await admin.query(`INSERT INTO timers(id,user_id,created_by,workspace_id,is_shared,status,record_status,type,target_minutes,accumulated_ms)
    VALUES ($1,$3,$3,$4,false,'idle','active','up',1,0),($2,$3,$3,$4,true,'idle','active','up',1,0)`,
    [ids.personal, ids.shared, ids.worker, ids.company]);

  for (const [id, actor] of [[ids.personal, ids.worker],
    [ids.personal, ids.superadmin], [ids.shared, ids.worker]]) {
    await writer.query("BEGIN");
    try {
      await writing(writer, id, { status: "running", ends_at: new Date(Date.now()+60000).toISOString() }, actor);
      await assert.rejects(() => closing(closer), error => error.code === "55P03");
      await writer.query("COMMIT");
    } catch (err) { await writer.query("ROLLBACK"); throw err; }
  }
  await closing(closer);
  const { rows } = await admin.query("SELECT id,status,archived_at,is_shared FROM timers WHERE id=ANY($1::uuid[])", [[ids.personal,ids.shared]]);
  assert.ok(rows.find(r => r.id === ids.personal).archived_at);
  assert.equal(rows.find(r => r.id === ids.shared).status, "running");
  assert.equal(rows.find(r => r.id === ids.shared).archived_at, null);
  await assert.rejects(() => writing(writer, ids.shared, { status: "paused" }), /KEEPTIMER_ACCOUNT_DISABLED/);
});

test("deactivation wins: late refresh, shared write, and duplicate closure wait then fail or return unchanged", { skip: !enabled }, async (t) => {
  const { admin, writer, closer } = await setup(t);
  await admin.query("INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,'hash')", [ids.session, ids.worker]);
  await admin.query(`INSERT INTO timers(id,user_id,created_by,workspace_id,is_shared,status,record_status,type,target_minutes,accumulated_ms)
    VALUES($1,$2,$2,$3,true,'running','active','up',1,0)`, [ids.shared, ids.worker, ids.company]);

  await closer.query("BEGIN");
  try {
    const first = await closing(closer);
    assert.equal(first.rows[0].result.already_disabled, false);
    await assert.rejects(() => writing(writer, ids.shared, { status: "paused" }), error => error.code === "55P03");
    await assert.rejects(() => writer.query("UPDATE sessions SET last_used_at=now() WHERE id=$1", [ids.session]), error => error.code === "55P03");
    await closer.query("COMMIT");
  } catch (err) { await closer.query("ROLLBACK"); throw err; }
  await assert.rejects(() => writing(writer, ids.shared, { status: "paused" }), /KEEPTIMER_ACCOUNT_DISABLED/);
  const again = await closing(closer);
  assert.equal(again.rows[0].result.already_disabled, true);
  assert.ok((await admin.query("SELECT revoked_at FROM sessions WHERE id=$1", [ids.session])).rows[0].revoked_at);
});
