import test from 'node:test';
import assert from 'node:assert/strict';
import { database, user, subscription, resolve, connect, localTestUrl } from './support/subscriptionPhase2.js';

const options = { skip: localTestUrl() ? false : 'Requires guarded isolated SUBSCRIPTION_TEST_DATABASE_URL + cluster marker' };
async function setup(t) {
  const admin = await database(t), a = await connect(t), b = await connect(t);
  for (const client of [a, b]) await client.exec("SET lock_timeout='250ms'");
  const owner = await user(admin);
  const row = await subscription(admin, { user_id: owner, starts_at: '2000-01-01Z', ends_at: '2100-01-01Z' });
  return { admin, a, b, owner, row };
}
const requirePaid = (db, id) => db.query('SELECT keeptimer_require_individual_entitlement($1) AS result', [id]);
const cancel = (db, row) => db.query('UPDATE subscriptions SET cancelled_at=clock_timestamp(),cancelled_by_user_id=$1 WHERE id=$2', [row.user_id, row.id]);

test('Phase 2 PG: same-transaction entitlement assertion blocks concurrent cancellation', options, async t => {
  const { a, b, owner, row } = await setup(t);
  await a.exec('BEGIN');
  try {
    await requirePaid(a, owner);
    await assert.rejects(() => cancel(b, row), e => e.code === '55P03');
    await a.exec('COMMIT');
  } catch (error) { await a.exec('ROLLBACK'); throw error; }
  await cancel(b, row);
  await assert.rejects(() => requirePaid(a, owner), /SUBSCRIPTION_CANCELLED/);
});

test('Phase 2 PG: cancellation first prevents a later paid authorization', options, async t => {
  const { a, b, owner, row } = await setup(t);
  await b.exec('BEGIN');
  try {
    await cancel(b, row);
    await assert.rejects(() => requirePaid(a, owner), e => e.code === '55P03');
    await b.exec('COMMIT');
  } catch (error) { await b.exec('ROLLBACK'); throw error; }
  await assert.rejects(() => requirePaid(a, owner), /SUBSCRIPTION_CANCELLED/);
});

test('Phase 2 PG: insert trigger prevents a history phantom during authorized transaction', options, async t => {
  const { a, b, owner } = await setup(t);
  const insert = () => subscription(b, { user_id: owner, sequence_no: 2, starts_at: '2001-01-01Z', ends_at: '2100-01-01Z' });
  await a.exec('BEGIN');
  try {
    await requirePaid(a, owner);
    await assert.rejects(insert, e => e.code === '55P03');
    await a.exec('COMMIT');
  } catch (error) { await a.exec('ROLLBACK'); throw error; }
  await insert();
  assert.equal((await resolve(a, owner)).code, 'SUBSCRIPTION_CONFLICT');
});

test('Phase 2 PG: catalog flag and disabled user cannot change during authorized transaction', options, async t => {
  const { a, b, owner } = await setup(t);
  await a.exec('BEGIN');
  try {
    await requirePaid(a, owner);
    await assert.rejects(() => b.exec("UPDATE subscription_plans SET enabled=false WHERE code='individual'"), e => e.code === '55P03');
    await assert.rejects(() => b.query('UPDATE users SET disabled_at=clock_timestamp() WHERE id=$1', [owner]), e => e.code === '55P03');
    await a.exec('COMMIT');
  } catch (error) { await a.exec('ROLLBACK'); throw error; }
  await b.exec("UPDATE subscription_plans SET enabled=false WHERE code='individual'");
  await assert.rejects(() => requirePaid(a, owner), /PLAN_DISABLED/);
});

test('Phase 2 PG: expiry is measured AFTER lock waits, not at transaction start', options, async t => {
  const { admin, a, b } = await setup(t);
  const owner = await user(admin);
  const row = (await admin.query(`INSERT INTO subscriptions(user_id,plan_code,sequence_no,starts_at,ends_at,term_months,amount_minor,created_by_user_id)
    VALUES($1,'individual',1,clock_timestamp()-interval '1 day',clock_timestamp()+interval '400 milliseconds',1,0,$1) RETURNING *`, [owner])).rows[0];
  await a.exec('BEGIN'); await a.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [owner]);
  await b.exec("SET lock_timeout='5s'; BEGIN");
  // Start b's transaction before the deadline. Its authorization waits on a.
  const pending = resolve(b, owner);
  try {
    await a.query("SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.03)", [row.ends_at]);
    await a.exec('COMMIT');
    const result = await pending;
    assert.equal(result.code, 'SUBSCRIPTION_EXPIRED');
    await b.exec('COMMIT');
  } catch (error) { await a.exec('ROLLBACK'); await b.exec('ROLLBACK'); throw error; }
});

test('Phase 2 PG: an uncommitted new period is seen after waiting for insert owner lock', options, async t => {
  const { admin, a, b } = await setup(t);
  const owner = await user(admin);
  await a.exec('BEGIN');
  try {
    await subscription(a, { user_id: owner, starts_at: '2000-01-01Z', ends_at: '2100-01-01Z' });
    await assert.rejects(() => resolve(b, owner), e => e.code === '55P03');
    await a.exec('COMMIT');
  } catch (error) { await a.exec('ROLLBACK'); throw error; }
  assert.equal((await resolve(b, owner)).isEntitled, true);
});
