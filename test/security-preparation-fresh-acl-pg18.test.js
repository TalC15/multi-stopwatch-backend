import test from 'node:test';
import {localTestUrl} from './support/subscriptionDatabase.js';
import {verifyFreshAcl} from './support/securityPreparationFreshAcl.js';
test('PG18 fresh ACL: real guarded PostgreSQL with no automatic Data API grants',{
 skip:localTestUrl()?false:'SKIP: guarded disposable PostgreSQL18 not configured; PGlite is not PG18 evidence',
},t=>verifyFreshAcl(t,{realPg18:true}));
