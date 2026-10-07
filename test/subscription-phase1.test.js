import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { database, phase1, user, subscription, asRole } from './support/subscriptionDatabase.js';

const rejectsCode = (fn, code) => assert.rejects(fn, e => e.code === code);

test('subscription Phase 1: database invariants and existing authority', async t => {
  const db = await database(t);
  await t.test('catalog codes and initial sales availability', async () => {
    assert.deepEqual((await db.query('SELECT code, enabled FROM subscription_plans ORDER BY code')).rows, [
      { code: 'enterprise', enabled: false }, { code: 'individual', enabled: true }, { code: 'team', enabled: false },
    ]);
    await rejectsCode(() => db.query("INSERT INTO subscription_plans(code,display_name) VALUES('agent','Bad')"), '23514');
    await rejectsCode(() => db.query("UPDATE subscription_plans SET code='premium' WHERE code='team'"), '23514');
    await rejectsCode(() => user(db, 'individual'), '23514');
  });
  await t.test('nullable plan/password/MFA defaults preserve legacy PIN writes', async () => {
    const id = await user(db);
    const row = (await db.query('SELECT plan_code,password_hash,must_change_password,mfa_email,pin_hash FROM users WHERE id=$1', [id])).rows[0];
    assert.deepEqual(row, { plan_code: null, password_hash: null, must_change_password: false, mfa_email: null, pin_hash: '$2b$12$fixtureHashOnly' });
    await rejectsCode(() => db.query("UPDATE users SET plan_code='bad' WHERE id=$1", [id]), '23503');
    await db.query("UPDATE users SET plan_code='individual',password_hash='one-way-hash',mfa_email='fixture@example.invalid' WHERE id=$1", [id]);
  });
  for (const term_months of [0, 13]) await t.test(`term ${term_months} rejected`, () =>
    rejectsCode(() => subscription(db, { term_months }), '23514'));
  for (const ends_at of ['2026-10-01T00:00:00Z', '2026-09-30T00:00:00Z', 'infinity']) await t.test(`invalid end ${ends_at} rejected`, () =>
    rejectsCode(() => subscription(db, { ends_at }), '23514'));
  await t.test('nonnegative bigint amount, positive sequence, currency and FKs', async () => {
    for (const extra of [{ amount_minor: -1 }, { sequence_no: 0 }, { currency: 'try' }, { currency: 'TRYX' }]) {
      await rejectsCode(() => subscription(db, extra), '23514');
    }
    await rejectsCode(() => subscription(db, { amount_minor: '1.5' }), '22P02');
    for (const extra of [{ plan_code: 'unknown' }, { user_id: randomUUID() }, { created_by_user_id: randomUUID() }]) {
      await rejectsCode(() => subscription(db, extra), '23503');
    }
    const row = await subscription(db, { amount_minor: '9007199254740993' });
    assert.equal(String(row.amount_minor), '9007199254740993');
    assert.equal(row.currency, 'TRY');
    assert.equal(String((await subscription(db, { amount_minor: 0 })).amount_minor), '0');
  });
  await t.test('unique sequence retains all 1/3/12-month renewal rows', async () => {
    const id = await user(db);
    for (const [sequence_no, term_months, starts_at, ends_at] of [
      [1, 1, '2026-01-01', '2026-02-01'], [2, 3, '2026-02-01', '2026-05-01'], [3, 12, '2026-05-01', '2027-05-01'],
    ]) await subscription(db, { user_id: id, sequence_no, term_months, starts_at, ends_at });
    await rejectsCode(() => subscription(db, { user_id: id, sequence_no: 2 }), '23505');
    assert.deepEqual((await db.query('SELECT sequence_no,term_months FROM subscriptions WHERE user_id=$1 ORDER BY sequence_no', [id])).rows,
      [{ sequence_no: 1, term_months: 1 }, { sequence_no: 2, term_months: 3 }, { sequence_no: 3, term_months: 12 }]);
    await rejectsCode(() => db.query('UPDATE subscriptions SET term_months=4 WHERE user_id=$1', [id]), '42501');
    await rejectsCode(() => db.query('DELETE FROM subscriptions WHERE user_id=$1', [id]), '42501');
    await rejectsCode(() => db.exec('TRUNCATE subscriptions'), '42501');
  });
  for (const role of ['superadmin', 'agent']) await t.test(`one active ${role}, replacement after disable, no reactivation`, async () => {
    const first = await user(db, role);
    await rejectsCode(() => user(db, role), '23505');
    const candidate = await user(db);
    await rejectsCode(() => db.query('UPDATE users SET role=$1 WHERE id=$2', [role, candidate]), '23505');
    await db.query('UPDATE users SET disabled_at=now() WHERE id=$1', [first]);
    await db.query('UPDATE users SET role=$1 WHERE id=$2', [role, candidate]);
    await user(db, role, { disabled_at: '2026-01-01T00:00:00Z' });
    await assert.rejects(() => db.query('UPDATE users SET disabled_at=NULL WHERE id=$1', [first]), /KEEPTIMER_ACCOUNT_REACTIVATION_BLOCKED/);
    assert.equal((await db.query('SELECT count(*)::int AS n FROM users WHERE role=$1 AND disabled_at IS NULL', [role])).rows[0].n, 1);
  });
  await t.test('subscription cancellation is atomic and history immutable thereafter', async () => {
    const row = await subscription(db);
    await rejectsCode(() => db.query('UPDATE subscriptions SET cancelled_at=now() WHERE id=$1', [row.id]), '23514');
    await db.query("UPDATE subscriptions SET cancelled_at=now(), cancelled_by_user_id=$1, cancellation_reason='Requested by customer' WHERE id=$2", [row.user_id, row.id]);
    await rejectsCode(() => db.query('UPDATE subscriptions SET cancelled_at=NULL,cancelled_by_user_id=NULL,cancellation_reason=NULL WHERE id=$1', [row.id]), '42501');
  });
  await t.test('expiry is derived without writes, timer changes or account deletion', async () => {
    const row = await subscription(db, { starts_at: '2000-01-01', ends_at: '2000-02-01' });
    const timerId = randomUUID();
    await db.query("INSERT INTO timers(id,user_id,name,type,target_minutes) VALUES($1,$2,'Retained','up',1)", [timerId, row.user_id]);
    const before = (await db.query('SELECT * FROM timers WHERE id=$1', [timerId])).rows;
    assert.equal((await db.query("SELECT CASE WHEN cancelled_at IS NOT NULL THEN 'cancelled' WHEN ends_at<=now() THEN 'expired' ELSE 'active' END AS status FROM subscriptions WHERE id=$1", [row.id])).rows[0].status, 'expired');
    assert.deepEqual((await db.query('SELECT * FROM timers WHERE id=$1', [timerId])).rows, before);
    assert.equal((await db.query('SELECT disabled_at FROM users WHERE id=$1', [row.user_id])).rows[0].disabled_at, null);
    await rejectsCode(() => db.query('DELETE FROM users WHERE id=$1', [row.user_id]), '23503');
    assert.deepEqual((await db.query('SELECT * FROM timers WHERE id=$1', [timerId])).rows, before);
  });
  await t.test('private workspace discriminator, owner, invite and shared flags', async () => {
    const owner = await user(db);
    const create = (kind, invite, shared, who = owner) => db.query('INSERT INTO workspaces(name,owner_id,kind,invite_code,shared_mode_enabled) VALUES(\'Private\',$1,$2,$3,$4)', [who, kind, invite, shared]);
    for (const args of [['bad', null, false], ['individual_private', 'invite', false], ['individual_private', null, true], ['individual_private', null, null], ['individual_private', null, false, null]]) {
      await rejectsCode(() => create(...args), '23514');
    }
    await create('individual_private', null, false);
    await rejectsCode(() => create('individual_private', null, false), '23505');
    assert.equal((await db.query("INSERT INTO workspaces(name) VALUES('Legacy') RETURNING kind")).rows[0].kind, 'team');
  });
  await t.test('RLS and ACL block clients despite broad default grants; service role has only intended grants', async () => {
    const owner = await user(db);
    await db.query("INSERT INTO admin_audit_log(actor_user_id,action,target_user_id) VALUES($1,'customer_created',$1)", [owner]);
    for (const role of ['anon', 'authenticated']) await asRole(db, role, async () => {
      for (const table of ['subscription_plans', 'subscriptions', 'admin_audit_log']) {
        for (const sql of [`SELECT * FROM ${table}`, `DELETE FROM ${table}`, `TRUNCATE ${table}`]) await rejectsCode(() => db.exec(sql), '42501');
      }
      await rejectsCode(() => db.exec("UPDATE admin_audit_log SET action='password_reset'"), '42501');
      await rejectsCode(() => db.query("INSERT INTO admin_audit_log(actor_user_id,action) VALUES($1,'password_reset')", [owner]), '42501');
    });
    // Prove RLS still denies access even if a future ordinary table grant slips in.
    await db.exec('GRANT SELECT, INSERT, UPDATE, DELETE ON admin_audit_log TO authenticated');
    await asRole(db, 'authenticated', async () => {
      assert.equal((await db.query('SELECT * FROM admin_audit_log')).rows.length, 0);
      await rejectsCode(() => db.query("INSERT INTO admin_audit_log(actor_user_id,action) VALUES($1,'password_reset')", [owner]), '42501');
      await rejectsCode(() => db.exec("UPDATE admin_audit_log SET action='password_reset'"), '42501');
      await rejectsCode(() => db.exec('DELETE FROM admin_audit_log'), '42501');
    });
    await db.exec('REVOKE ALL ON admin_audit_log FROM authenticated');
    await asRole(db, 'service_role', async () => {
      assert.equal((await db.query('SELECT * FROM subscription_plans')).rows.length, 3);
      const row = await subscription(db, { user_id: owner, created_by_user_id: owner });
      await db.query('UPDATE subscriptions SET cancelled_at=now(),cancelled_by_user_id=$1 WHERE id=$2', [owner, row.id]);
      await db.query("INSERT INTO admin_audit_log(actor_user_id,action,metadata) VALUES($1,'subscription_cancelled',$2)", [owner, JSON.stringify({ subscription_id: row.id, sequence_no: 1, plan_code: 'individual' })]);
      for (const sql of ["UPDATE subscription_plans SET enabled=true", 'DELETE FROM admin_audit_log', 'TRUNCATE admin_audit_log', "UPDATE subscriptions SET amount_minor=0", 'DELETE FROM subscriptions']) {
        await rejectsCode(() => db.exec(sql), '42501');
      }
    });
    assert.equal((await db.query("SELECT count(*)::int AS n FROM pg_class WHERE oid IN ('subscription_plans'::regclass,'subscriptions'::regclass,'admin_audit_log'::regclass) AND relrowsecurity")).rows[0].n, 3);
  });
  await t.test('audit append-only and strict metadata prevent secret/request dumps', async () => {
    const owner = await user(db);
    for (const metadata of [null, [], { password: 'x' }, { pin: 'x' }, { otp: 'x' }, { access_token: 'x' }, { refresh_token: 'x' }, { mfa_email: 'x' }, { request: { password: 'x' } }, { plan_code: { password: 'x' } }, { subscription_id: 'not-a-uuid' }, { sequence_no: 'secret' }, { sequence_no: null }]) {
      await assert.rejects(() => db.query("INSERT INTO admin_audit_log(actor_user_id,action,metadata) VALUES($1,'password_reset',$2)", [owner, JSON.stringify(metadata)]), e => ['23514', '22P02'].includes(e.code));
    }
    for (const action of ['customer_created', 'subscription_created', 'subscription_renewed', 'subscription_cancelled', 'password_reset', 'agent_created', 'agent_revoked']) {
      await db.query('INSERT INTO admin_audit_log(actor_user_id,action,target_user_id) VALUES($1,$2,$1)', [owner, action]);
    }
    for (const sql of ["UPDATE admin_audit_log SET action='password_reset'", 'DELETE FROM admin_audit_log', 'TRUNCATE admin_audit_log']) await rejectsCode(() => db.exec(sql), '42501');
    await rejectsCode(() => db.query('DELETE FROM users WHERE id=$1', [owner]), '23503');
  });
  await t.test('existing company/workspace guards stop timer cascades', async () => {
    const workspace = (await db.query("INSERT INTO workspaces(name) VALUES('Team') RETURNING id")).rows[0].id;
    const owner = await user(db, 'worker', { workspace_id: workspace });
    const id = randomUUID();
    await db.query("INSERT INTO timers(id,user_id,created_by,workspace_id,name,type,target_minutes) VALUES($1,$2,$2,$3,'Company','up',1)", [id, owner, workspace]);
    await assert.rejects(() => db.query('DELETE FROM users WHERE id=$1', [owner]), /COMPANY_USER_DELETE_BLOCKED/);
    await assert.rejects(() => db.query('DELETE FROM workspaces WHERE id=$1', [workspace]), /WORKSPACE_HISTORY_PROTECTED/);
    assert.equal((await db.query('SELECT count(*)::int AS n FROM timers WHERE id=$1', [id])).rows[0].n, 1);
  });
  await t.test('documented legacy risk: workspace-null user deletion CAN cascade a creator-null timer', async () => {
    const owner = await user(db), id = randomUUID();
    await db.query("INSERT INTO timers(id,user_id,created_by,workspace_id,name,type,target_minutes) VALUES($1,$2,NULL,NULL,'Legacy','up',1)", [id, owner]);
    await db.query('DELETE FROM users WHERE id=$1', [owner]);
    assert.equal((await db.query('SELECT count(*)::int AS n FROM timers WHERE id=$1', [id])).rows[0].n, 0);
  });
  await t.test('replay preserves records, catalogue choice and timers', async () => {
    await db.exec("UPDATE subscription_plans SET enabled=false WHERE code='individual'");
    const query = "SELECT (SELECT count(*) FROM users)::int AS users, (SELECT count(*) FROM subscriptions)::int AS subscriptions, (SELECT count(*) FROM admin_audit_log)::int AS audit, (SELECT jsonb_agg(t ORDER BY id) FROM timers t) AS timers";
    const before = (await db.query(query)).rows;
    await db.exec(phase1);
    assert.deepEqual((await db.query(query)).rows, before);
    assert.equal((await db.query("SELECT enabled FROM subscription_plans WHERE code='individual'")).rows[0].enabled, false);
  });
});

test('subscription Phase 1 preflight fails atomically on multiple existing superadmins', async t => {
  const db = await database(t, { migrate: false });
  await user(db, 'superadmin'); await user(db, 'superadmin');
  await assert.rejects(() => db.exec(phase1), /KEEPTIMER_PHASE1_ACTIVE_ROLE_CONFLICT: superadmin=2/);
  await db.exec('ROLLBACK');
  assert.equal((await db.query("SELECT to_regclass('public.subscription_plans') AS table_name")).rows[0].table_name, null);
  assert.equal((await db.query("SELECT count(*)::int AS n FROM users WHERE role='superadmin' AND disabled_at IS NULL")).rows[0].n, 2);
  assert.equal((await db.query("SELECT count(*)::int AS n FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='password_hash'")).rows[0].n, 0);
});
