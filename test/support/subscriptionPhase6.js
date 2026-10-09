import { readFile } from 'node:fs/promises';
import { database as previous } from './subscriptionPhase5.js';
export * from './subscriptionPhase5.js';
export { command, enableIsolatedFixture, saleData } from './subscriptionPhase3.js';
export const phase6 = await readFile(new URL('../../db/migrations/20261009_subscription_lifecycle.sql', import.meta.url), 'utf8');
export async function database(t) { const db = await previous(t); await db.exec(phase6); return db; }
export const renewal = id => ({ customer_id: id, plan_code: 'individual', term_months: 1, amount_minor: 10000, currency: 'TRY' });
export const cancel = (customer, period) => ({ customer_id: customer, subscription_id: period, reason: 'customer_request' });
