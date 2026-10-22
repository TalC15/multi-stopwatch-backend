import test from 'node:test';
import {verifyFreshAcl} from './support/securityPreparationFreshAcl.js';
test('fresh ACL: no automatic Data API grants, sensitive tables stay RPC-only',verifyFreshAcl);
