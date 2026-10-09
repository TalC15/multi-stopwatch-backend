import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { seededCustomer as previousCustomer } from './subscriptionPhase3.js';
import { database as previous } from './subscriptionPhase3.js';
export { user, subscription, actor, asRole, connect, localTestUrl, resolve } from './subscriptionPhase3.js';
export const migration = await readFile(new URL('../../db/migrations/20261008_subscription_workspace_private_access.sql', import.meta.url), 'utf8');
export async function database(t) { const db = await previous(t); await db.exec(migration); return db; }
export async function seededCustomer(db, actor, period) {
  const c = await previousCustomer(db, actor, period); c.session = randomUUID();
  await db.query('INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,$3)', [c.session,c.id,'synthetic-private-session']);
  return c;
}
export async function scope(db, id, write = false) {
  return (await db.query('SELECT public.keeptimer_phase5_scope($1,$2) r', [id, write])).rows[0].r;
}
export const state = extra => ({ name: 'Private fixture', type: 'down', target_minutes: 5, is_pay: false,
  status: 'idle', ends_at: null, ended_at: null, duration_ms: null, accumulated_ms: 0, paused_count: 0, ...extra });
export async function put(db, owner, id, mutation, revision = 0, value = state()) {
  return (await db.query('SELECT public.keeptimer_sync_personal($1,$2,$3,$4,$5,$6) r', [owner, id, mutation, revision, JSON.stringify(value), (await db.query('SELECT id FROM sessions WHERE user_id=$1 LIMIT 1', [owner])).rows[0]?.id ?? null])).rows[0].r;
}
export async function remove(db, owner, id, mutation, revision) {
  return (await db.query('SELECT public.keeptimer_delete_personal($1,$2,$3,$4,$5) r', [owner, id, mutation, revision, (await db.query('SELECT id FROM sessions WHERE user_id=$1 LIMIT 1', [owner])).rows[0]?.id ?? null])).rows[0].r;
}
