// Prepared regression; not executed during source synchronization.
// Synthetic adapters only. This proves ordering, not a real PostgreSQL budget.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPasswordAuth } from '../src/passwordAuth.js';

for (const transport of ['web', 'native']) {
  for (const failure of ['exhausted', 'database-error', 'transport-error']) {
    test(`password login ${transport}: ${failure} stops before account lookup and side effects`, async () => {
      const calls = [], effects = [];
      const db = {
        rpc: async (name, args) => {
          calls.push({ name, args });
          assert.equal(name, 'keeptimer_auth_limit', 'no account lookup/session RPC before budget approval');
          if (failure === 'transport-error') throw new Error('synthetic unavailable database');
          return failure === 'exhausted' ? { data: false, error: null } : { data: null, error: { code: 'synthetic-db-error' } };
        },
        from: () => { effects.push('table-access'); assert.fail('no table access before budget approval'); },
      };
      const core = createPasswordAuth({ db, tokens: {},
        env: { AUTH_TOKEN_HMAC_KEY: 'a'.repeat(64), AUTH_RATE_HMAC_KEY: 'b'.repeat(64) },
        mail: { configured: () => false, send: async () => { effects.push('mail'); assert.fail('no provider send'); } },
      });
      const code = failure === 'exhausted' ? 'AUTH_RATE_LIMITED' : 'AUTH_UNAVAILABLE';
      await assert.rejects(core.passwordLogin({ email: ' SYNTHETIC@example.test ',
        password: 'Synthetic-only-password-2026' }, '192.0.2.8', transport), error => error.code === code);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].name, 'keeptimer_auth_limit');
      assert.deepEqual(Object.keys(calls[0].args).sort(), ['p_account', 'p_ip', 'p_kind']);
      assert.equal(calls[0].args.p_kind, 'login');
      assert.match(calls[0].args.p_account, /^[a-f0-9]{64}$/);
      assert.match(calls[0].args.p_ip, /^[a-f0-9]{64}$/);
      assert.notEqual(calls[0].args.p_account, calls[0].args.p_ip);
      assert.ok(!JSON.stringify(calls).includes('example.test'));
      assert.ok(!JSON.stringify(calls).includes('192.0.2.8'));
      assert.deepEqual(effects, []);
    });
  }
}
