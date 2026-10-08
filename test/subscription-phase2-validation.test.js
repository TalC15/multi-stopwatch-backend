import test from 'node:test';
import assert from 'node:assert/strict';
import { createSubscriptionCore } from '../src/subscriptions.js';

const userId = '12345678-1234-1234-1234-123456789abc';
const active = {
  planCode: 'individual', status: 'active',
  startsAt: '2026-10-01T00:00:00Z', endsAt: '2026-11-01T00:00:00Z',
  isEntitled: true, requiresSubscription: true, code: null,
};
const denial = code => ({
  planCode: null, status: null, startsAt: null, endsAt: null,
  isEntitled: false, requiresSubscription: true, code,
});
const coreFor = data => createSubscriptionCore({ rpc: async (name, args) => {
  assert.equal(name, 'keeptimer_resolve_entitlement');
  assert.deepEqual(args, { p_user_id: userId });
  return { data, error: null };
} });
const unavailable = error => error.status === 503 && error.body.code === 'SUBSCRIPTION_UNAVAILABLE';

test('Phase 2 RPC code validation rejects coercible and unknown codes', async t => {
  for (const [name, code] of [
    ['account array', ['ACCOUNT_DISABLED']],
    ['conflict array', ['SUBSCRIPTION_CONFLICT']],
    ['unavailable array', ['SUBSCRIPTION_UNAVAILABLE']],
    ['object', {}], ['number', 123], ['true', true], ['false', false],
    ['unknown string', 'UNKNOWN_CODE'], ['missing code', undefined],
  ]) await t.test(name, async () => {
    const core = coreFor(denial(code));
    await assert.rejects(() => core.resolveSubscriptionEntitlement(userId), unavailable);
    assert.equal((await core.currentAccountScopeError(userId)).status, 503);
  });
});

test('Phase 2 valid string codes retain protected-operation HTTP mappings', async t => {
  for (const [code, status] of [
    ['ACCOUNT_DISABLED', 401], ['SUBSCRIPTION_REQUIRED', 403],
    ['SUBSCRIPTION_PENDING', 403], ['SUBSCRIPTION_EXPIRED', 403],
    ['SUBSCRIPTION_CANCELLED', 403], ['PLAN_DISABLED', 403],
    ['SUBSCRIPTION_FORBIDDEN', 403], ['SUBSCRIPTION_CONFLICT', 409],
    ['INDIVIDUAL_SCOPE_NOT_READY', 403], ['SUBSCRIPTION_UNAVAILABLE', 503],
  ]) await t.test(code, async () => {
    const result = denial(code), core = coreFor(result);
    assert.deepEqual(await core.resolveSubscriptionEntitlement(userId), result);
    const error = await core.currentAccountScopeError(userId);
    assert.equal(error.status, status); assert.equal(error.body.code, code);
  });
});

test('Phase 2 null code remains valid for active Individual; legacy remains explicit', async () => {
  const core = coreFor(active);
  assert.deepEqual(await core.resolveSubscriptionEntitlement(userId), active);
  assert.equal((await core.currentAccountScopeError(userId)).body.code, 'INDIVIDUAL_SCOPE_NOT_READY');
  await assert.rejects(() => coreFor({ ...active, isEntitled: false }).resolveSubscriptionEntitlement(userId), unavailable);
  assert.equal(await coreFor({ ...denial('SUBSCRIPTION_REQUIRED'), requiresSubscription: false }).currentAccountScopeError(userId), null);
});

test('Phase 2 timestamp ordering preserves microseconds and timezone offsets', async t => {
  for (const [name, startsAt, endsAt, accepted] of [
    ['one microsecond in same millisecond', '2026-10-01T00:00:00.000001+00:00', '2026-10-01T00:00:00.000002+00:00', true],
    ['equal microsecond', '2026-10-01T00:00:00.000001Z', '2026-10-01T00:00:00.000001Z', false],
    ['one microsecond reversed', '2026-10-01T00:00:00.000002Z', '2026-10-01T00:00:00.000001Z', false],
    ['normal monthly period', '2026-10-01T00:00:00Z', '2026-11-01T00:00:00+00:00', true],
    ['equal absolute times with different offsets', '2026-10-01T03:00:00.000001+03:00', '2026-09-30T20:00:00.000001-04:00', false],
    ['valid period opposite to lexical order', '2026-10-01T03:00:00.000001+03:00', '2026-09-30T20:00:00.000002-04:00', true],
    ['reversed period despite increasing local dates', '2026-09-30T20:00:00.000002-04:00', '2026-10-01T03:00:00.000001+03:00', false],
    ['fractional-hour offsets', '2026-10-01T05:45:00.000001+05:45', '2026-09-30T20:30:00.000002-03:30', true],
    ['basic ISO offset', '2026-10-01T03:00:00.000001+0300', '2026-10-01T00:00:00.000002Z', true],
    ['PostgreSQL short offset', '2026-10-01T00:00:00.000001+00', '2026-10-01T00:00:00.000002+00', true],
    ['PostgreSQL space separator', '2026-10-01 00:00:00.000001+00', '2026-10-01 00:00:00.000002+00', true],
    ['one fractional digit padded to microseconds', '2026-10-01T00:00:00.1Z', '2026-10-01T00:00:00.100001Z', true],
    ['three fractional digits padded to microseconds', '2026-10-01T00:00:00.123Z', '2026-10-01T00:00:00.123001Z', true],
    ['before epoch', '1969-12-31T23:59:59.999998Z', '1969-12-31T23:59:59.999999Z', true],
    ['across epoch', '1969-12-31T23:59:59.999999Z', '1970-01-01T00:00:00Z', true],
    ['far future avoids unsafe integer microseconds', '9999-12-31T23:59:59.000001Z', '9999-12-31T23:59:59.000002Z', true],
    ['leap day', '2024-02-29T23:59:59.999999Z', '2024-03-01T00:00:00Z', true],
  ]) await t.test(name, async () => {
    const result = { ...active, startsAt, endsAt }, core = coreFor(result);
    if (accepted) assert.deepEqual(await core.resolveSubscriptionEntitlement(userId), result);
    else await assert.rejects(() => core.resolveSubscriptionEntitlement(userId), unavailable);
  });
});

test('Phase 2 malformed timestamps cannot be normalized into valid periods', async t => {
  for (const invalid of [
    'not-a-timestamp', 'infinity', '', null, 123,
    '2026-02-29T00:00:00Z', '2026-02-30T00:00:00Z', '2026-04-31T00:00:00Z',
    '2026-13-01T00:00:00Z', '2026-10-00T00:00:00Z', '2026-10-01T24:00:00Z',
    '2026-10-01T00:60:00Z', '2026-10-01T00:00:60Z',
    '2026-10-01T00:00:00+24:00', '2026-10-01T00:00:00+00:60',
    '2026-10-01T00:00:00.0000001Z', '2026-10-01T00:00:00.Z',
    '2026-10-01', '2026-10-01T00:00:00', '2026-10-01T00:00:00Zjunk',
    '2026-10-01T00:00:00Z\n', '2026-10-01T00:00:00Z\r\n',
  ]) await t.test(String(invalid), async () => {
    for (const field of ['startsAt', 'endsAt']) {
      await assert.rejects(() => coreFor({ ...active, [field]: invalid }).resolveSubscriptionEntitlement(userId), unavailable);
    }
  });
});
