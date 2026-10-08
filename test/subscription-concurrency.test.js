import test from 'node:test';
import assert from 'node:assert/strict';
import { database, connect, localTestUrl, user, subscription } from './support/subscriptionPhase2.js';

const options = { skip: localTestUrl() ? false : 'Requires disposable local SUBSCRIPTION_TEST_DATABASE_URL' };

async function connections(t) {
  const admin = await database(t);
  const a = await connect(t), b = await connect(t);
  await b.exec("SET lock_timeout='250ms'");
  return { admin, a, b };
}

for (const role of ['superadmin', 'agent']) {
  test(`subscription PG: concurrent ${role} inserts cannot both commit`, options, async t => {
    const { admin, a, b } = await connections(t);
    await a.exec('BEGIN');
    try {
      await user(a, role);
      await assert.rejects(() => user(b, role), e => e.code === '55P03');
      await a.exec('COMMIT');
    } catch (error) { await a.exec('ROLLBACK'); throw error; }
    await assert.rejects(() => user(b, role), e => e.code === '23505');
    assert.equal((await admin.query('SELECT count(*)::int AS n FROM users WHERE role=$1 AND disabled_at IS NULL', [role])).rows[0].n, 1);
  });

  test(`subscription PG: ${role} replacement waits for committed disable`, options, async t => {
    const { admin, a, b } = await connections(t);
    const first = await user(admin, role);
    await a.exec('BEGIN');
    try {
      await a.query('UPDATE users SET disabled_at=now() WHERE id=$1', [first]);
      await assert.rejects(() => user(b, role), e => e.code === '55P03');
      await a.exec('COMMIT');
    } catch (error) { await a.exec('ROLLBACK'); throw error; }
    await user(b, role);
    await assert.rejects(() => user(admin, role), e => e.code === '23505');
    assert.equal((await admin.query('SELECT count(*)::int AS n FROM users WHERE role=$1 AND disabled_at IS NULL', [role])).rows[0].n, 1);
  });
}

test('subscription PG: concurrent renewal sequence is unique; loser must retry with a new sequence', options, async t => {
  const { admin, a, b } = await connections(t);
  const owner = await user(admin);
  await a.exec('BEGIN');
  try {
    await subscription(a, { user_id: owner });
    await assert.rejects(() => subscription(b, { user_id: owner }), e => e.code === '55P03');
    await a.exec('COMMIT');
  } catch (error) { await a.exec('ROLLBACK'); throw error; }
  await assert.rejects(() => subscription(b, { user_id: owner }), e => e.code === '23505');
  await subscription(b, { user_id: owner, sequence_no: 2 });
  assert.deepEqual((await admin.query('SELECT sequence_no FROM subscriptions WHERE user_id=$1 ORDER BY sequence_no', [owner])).rows, [{ sequence_no: 1 }, { sequence_no: 2 }]);
});
