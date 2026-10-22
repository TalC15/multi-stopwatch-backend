// Child process used only by guarded GitHub PG18 tests. No live provider.
import express from 'express';
import {connect} from './subscriptionDatabase.js';
import {rpcAdapter} from './mfaDevice.js';
import {mountPasswordAuth} from '../../src/passwordAuth.js';
import {createWebAuthGuard,webAuthErrorHandler} from '../../src/webAuth.js';
if(process.env.GITHUB_ACTIONS!=='true'||process.env.KT_CI_RUNNER_ENVIRONMENT!=='github-hosted')throw Error('GitHub hosted only');
let close;const db=await connect({after:fn=>{close=fn;}}),origin='https://fixture.example';
const app=express();app.use('/auth',createWebAuthGuard(new Set([origin])));app.use(express.json());
const core=mountPasswordAuth({app,db:rpcAdapter(db),tokens:{},authenticate:(_req,res)=>res.sendStatus(401),mail:{configured:()=>false,send:()=>{throw Error('No mail');}},env:{AUTH_TOKEN_HMAC_KEY:'a'.repeat(64),AUTH_RATE_HMAC_KEY:'b'.repeat(64)}});
app.use(webAuthErrorHandler);const server=app.listen(0,'127.0.0.1',()=>process.send?.({port:server.address().port}));
process.on('SIGTERM',async()=>{core.stopWorker();server.closeAllConnections();await new Promise(r=>server.close(r));await close?.();process.exit(0);});
