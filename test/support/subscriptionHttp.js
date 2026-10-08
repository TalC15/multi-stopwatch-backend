// Explicit empty-history response for legacy regression fixtures. Paid account
// behavior is tested separately; absence/malformed RPC responses never allow access.
export const legacyEntitlement = Object.freeze({ planCode: null, status: null,
  startsAt: null, endsAt: null, isEntitled: false, requiresSubscription: false,
  code: 'SUBSCRIPTION_REQUIRED' });
export const legacySubscriptionResponse = () => new Response(JSON.stringify(legacyEntitlement),
  { headers: { 'Content-Type': 'application/json' } });
