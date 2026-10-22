// Local source integrity only. Isolated GitHub jobs have no Render dependency.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const file = 'preparation/source-readiness.json';
const state = JSON.parse(fs.readFileSync(file,'utf8'));
const stop = reason => { console.error(`BLOCKED: ${reason}`); process.exit(2); };
if (state.localSourceStatus !== 'CONFIRMED_CURRENT') stop('current local source not reviewed');
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const safeRelative = name => typeof name === 'string' && !path.isAbsolute(name) && !name.split(/[\\/]/).includes('..');
if (!/^[a-f0-9]{40}$/.test(state.localRevision || '')) stop('reviewed local revision missing');
const sums=fs.readFileSync('preparation/source-SHA256SUMS');
if (digest(sums)!==state.sourceManifestSha256) stop('committed source manifest changed');
const committed=JSON.parse(fs.readFileSync('preparation/source-hashes.json','utf8'));
const canonical=Object.entries(committed).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([name,sha])=>`${sha}  ${name}\n`).join('');
if (digest(canonical)!==state.sourceManifestSha256) stop('source hash map differs from canonical manifest');
for (const [name,sha] of Object.entries(committed)) {
  if (!safeRelative(name) || !/^[a-f0-9]{64}$/.test(sha)) stop('invalid committed source entry');
  if (digest(fs.readFileSync(name))!==sha) stop(`committed source changed: ${name}`);
}
const hashes = state.localProductHashesApproved || {};
for (const required of ['src/server.js','src/passwordAuth.js']) if (!hashes[required]) stop('product hash review incomplete');
for (const [name,sha256] of Object.entries(hashes)) {
  if (!safeRelative(name) || !/^(?:src\/|db\/migrations\/)/.test(name)) stop('invalid product manifest path');
  if (committed[name]!==sha256) stop(`product review differs from committed manifest: ${name}`);
  if (digest(fs.readFileSync(name)) !== sha256) stop(`prepared source changed: ${name}`);
}
const tests=JSON.parse(fs.readFileSync('preparation/test-file-inventory.json','utf8'));
if (tests.revision!==state.localRevision) stop('test inventory revision changed');
for (const entry of tests.files) {
  if (!safeRelative(entry.file) || !/^test\/[^/]+\.test\.js$/.test(entry.file)) stop('invalid test inventory entry');
  if (digest(fs.readFileSync(entry.file))!==entry.sha256) stop(`test input changed: ${entry.file}`);
}
const actualTests=fs.readdirSync('test').filter(n=>n.endsWith('.test.js')).sort();
if (JSON.stringify(actualTests)!==JSON.stringify(tests.files.map(e=>e.file.slice(5)).sort())) stop('test file set differs from inventory');
for (const entry of tests.supportFiles || []) {
  if (!safeRelative(entry.file) || !/^test\/support\/[^/]+\.js$/.test(entry.file)) stop('invalid test support entry');
  if (digest(fs.readFileSync(entry.file))!==entry.sha256) stop(`test support changed: ${entry.file}`);
}
const actualSupport=fs.readdirSync('test/support').filter(n=>n.endsWith('.js')).sort();
if (JSON.stringify(actualSupport)!==JSON.stringify((tests.supportFiles || []).map(e=>e.file.slice(13)).sort())) stop('test support file set differs from inventory');
console.log('READY: reviewed local source and test inputs intact. Isolated jobs require existing DB guards, not Render. No tests started.');
