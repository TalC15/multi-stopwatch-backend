import test from 'node:test';
import assert from 'node:assert/strict';
import {sendTelegramMessage} from '../src/telegram.js';
for(const outcome of ['accepted','rejected','thrown'])test('Telegram '+outcome+' logs contain no recipient, message or token',async t=>{
 const logs=[],recipient='-100123456789',body='private fixture message',token='synthetic-fixture-token';
 t.mock.method(console,'log',(...args)=>logs.push(args));t.mock.method(console,'error',(...args)=>logs.push(args));
 const old=process.env.TELEGRAM_BOT_TOKEN;process.env.TELEGRAM_BOT_TOKEN=token;
 t.after(()=>{if(old===undefined)delete process.env.TELEGRAM_BOT_TOKEN;else process.env.TELEGRAM_BOT_TOKEN=old;});
 t.mock.method(globalThis,'fetch',async url=>{
  assert.equal(new URL(url).searchParams.get('chat_id'),recipient);
  if(outcome==='thrown')throw Error(url+' '+body);
  return {json:async()=>({ok:outcome==='accepted',description:recipient+' '+token+' '+body})};
 });
 await sendTelegramMessage(recipient,body);assert.equal(logs.length,1);
 for(const sensitive of [recipient,body,token])assert.equal(logs.flat().map(String).join(' ').includes(sensitive),false);
});
