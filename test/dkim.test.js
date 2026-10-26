import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { checkDkim, parseDkim, lintDkim } from '../src/index.js';

const spki = (bits) => generateKeyPairSync('rsa', { modulusLength: bits }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const KEY2048 = spki(2048);
const KEY1024 = spki(1024);
const KEY512 = spki(512);
const ED = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');

const dns = (map) => async (name) => {
  if (!(name in map)) { const e = new Error('not found'); e.code = 'ENOTFOUND'; throw e; }
  return map[name];
};
const codes = (list) => list.map((i) => i.code);

test('decodes RSA key length', () => {
  const p = parseDkim(`v=DKIM1; k=rsa; p=${KEY2048}`);
  assert.deepEqual(p.errors, []);
  assert.equal(p.key.bits, 2048);
  assert.deepEqual(lintDkim(p), []);
});

test('decodes Ed25519 keys', () => {
  const p = parseDkim(`v=DKIM1; k=ed25519; p=${ED}`);
  assert.deepEqual(p.errors, []);
  assert.equal(p.key.type, 'ed25519');
});

test('flags short and weak keys', () => {
  assert.ok(codes(lintDkim(parseDkim(`v=DKIM1; p=${KEY1024}`))).includes('short-key'));
  assert.ok(codes(lintDkim(parseDkim(`v=DKIM1; p=${KEY512}`))).includes('weak-key'));
});

test('revoked, testing and sha1-only keys', () => {
  const c = codes(lintDkim(parseDkim(`v=DKIM1; t=y; h=sha1; p=${KEY2048}`)));
  assert.ok(c.includes('testing'));
  assert.ok(c.includes('sha1-only'));
  assert.ok(codes(lintDkim(parseDkim('v=DKIM1; p='))).includes('revoked'));
});

test('syntax errors', () => {
  assert.ok(parseDkim('v=DKIM1; k=rsa').errors.some((e) => e.includes('"p"')));
  assert.ok(parseDkim('v=DKIM2; p=!!!').errors.length >= 2);
  assert.ok(parseDkim('v=DKIM1; p=QUJD').errors.some((e) => e.includes('cannot be decoded')));
});

test('handles keys split across strings with whitespace', () => {
  const half = Math.floor(KEY2048.length / 2);
  const p = parseDkim(`v=DKIM1; p=${KEY2048.slice(0, half)} ${KEY2048.slice(half)}`);
  assert.equal(p.key.bits, 2048);
});

test('checks explicit selectors', async () => {
  const r = await checkDkim('example.com', { selectors: ['s1', 'missing'], resolveTxt: dns({ 's1._domainkey.example.com': [`v=DKIM1; p=${KEY2048}`] }) });
  assert.equal(r.selectors.length, 2);
  assert.equal(r.selectors[0].found, true);
  assert.equal(r.selectors[1].found, false);
  assert.ok(r.ok);
});

test('probes common selectors when none given', async () => {
  const r = await checkDkim('https://Example.com/', { resolveTxt: dns({ 'google._domainkey.example.com': [`v=DKIM1; p=${KEY1024}`] }) });
  assert.equal(r.probed, true);
  assert.deepEqual(r.selectors.map((s) => s.selector), ['google']);
  assert.ok(codes(r.issues).includes('short-key'));
});

test('reports missing keys', async () => {
  const probe = await checkDkim('example.com', { resolveTxt: dns({}) });
  assert.ok(codes(probe.issues).includes('no-selector-found'));
  assert.equal(probe.ok, false);
  const explicit = await checkDkim('example.com', { selectors: ['x'], resolveTxt: dns({}) });
  assert.ok(codes(explicit.issues).includes('no-dkim'));
});
