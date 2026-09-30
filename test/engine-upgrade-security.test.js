import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createSocketServer } from '../src/socketServer.js';
import WebSocket from 'ws';

test('Application Engine.IO rejects omitted/mismatched upgrade protocol while retaining normal websocket upgrades', { timeout: 8000 }, async () => {
  const http = createServer(), io = createSocketServer(http), sockets = [];
  http.listen(0, '127.0.0.1'); await once(http, 'listening');
  const port = http.address().port;
  try {
    for (const protocol of ['3', null, '4']) {
      const handshake = await fetch(`http://127.0.0.1:${port}/socket.io/?EIO=4&transport=polling`);
      const packet = await handshake.text(); assert.equal(packet[0], '0'); const { sid } = JSON.parse(packet.slice(1));
      const result = await new Promise(resolve => {
        const ws = new WebSocket(`ws://127.0.0.1:${port}/socket.io/?transport=websocket&sid=${sid}${protocol === null ? '' : '&EIO=' + protocol}`);
        sockets.push(ws); ws.on('error', () => {});
        ws.once('unexpected-response', (_request, response) => { response.resume(); ws.terminate(); resolve(response.statusCode); });
        ws.once('open', () => { ws.terminate(); resolve(101); });
      });
      assert.equal(result, protocol === '4' ? 101 : 400);
    }
  } finally {
    for (const ws of sockets) ws.terminate(); http.closeAllConnections();
    await new Promise(resolve => io.close(resolve));
  }
});
