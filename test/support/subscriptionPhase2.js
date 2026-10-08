import { readFile } from 'node:fs/promises';
import { database as phase1Database } from './subscriptionDatabase.js';
export { user, subscription, asRole, connect, localTestUrl } from './subscriptionDatabase.js';
export const phase2 = await readFile(new URL('../../db/migrations/20261008_subscription_entitlement_core.sql', import.meta.url), 'utf8');
export async function database(t) {
  const db = await phase1Database(t);
  await db.exec(phase2);
  return db;
}
export async function resolve(db, userId) {
  return (await db.query('SELECT public.keeptimer_resolve_entitlement($1) AS result', [userId])).rows[0].result;
}
