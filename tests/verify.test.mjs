// Tests of verify.mjs on recorded proofs (node --test). No network: the chain is a fake fetch.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { chainKey, main, rootsCalldata, MAINNET_CONTRACT } from '../verify.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const REAL = join(here, 'fixtures', 'proof-2026-09-30-candle.json');
const EXAMPLE = join(here, 'fixtures', 'example-proof.json');
const ROOT = '793d6b654abc9df5253cfd33d8e8d2459018880f9353ef3294d8b4607f6de60a';

const chain = (word, status = 200) => {
  const sent = [];
  const fetcher = async (url, init) => { sent.push({ url, init, body: JSON.parse(init.body) }); return { ok: status === 200, status, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x' + word }) }; };
  return { fetcher, sent };
};

const run = async (argv, fetcher = chain(ROOT).fetcher) => {
  const lines = [];
  const code = await main(argv, { fetcher, say: (l) => lines.push(l) });
  return { code, said: lines.join('\n') };
};

const tampered = (change) => {
  const proof = JSON.parse(readFileSync(REAL, 'utf8'));
  change(proof);
  const file = join(mkdtempSync(join(tmpdir(), 'debyko-')), 'proof.json');
  writeFileSync(file, JSON.stringify(proof));
  return file;
};

test('the real proof of a 2026-09-30 candle is valid against the chain, asked with eth_call roots(20260930) and a User-Agent', async () => {
  const { fetcher, sent } = chain(ROOT);
  const { code, said } = await run([REAL], fetcher);
  assert.equal(code, 0, said);
  assert.match(said, /✓ valid/);
  assert.equal(sent[0].url, 'https://mainnet.base.org');
  assert.match(sent[0].init.headers['user-agent'], /^debyko-verify\//);
  assert.equal(sent[0].body.params[0].to, MAINNET_CONTRACT);
  assert.equal(sent[0].body.params[0].data, rootsCalldata(20260930));
});

test('another RPC, another root, an empty slot, a refusing RPC', async () => {
  const { fetcher, sent } = chain(ROOT);
  assert.equal((await run([REAL, '--rpc', 'https://base.drpc.org'], fetcher)).code, 0);
  assert.equal(sent[0].url, 'https://base.drpc.org');
  assert.equal((await run([REAL], chain('ab'.repeat(32)).fetcher)).code, 1);
  assert.equal((await run([REAL], chain('0'.repeat(64)).fetcher)).code, 1);
  const refused = await run([REAL], chain(ROOT, 403).fetcher);
  assert.equal(refused.code, 2);
  assert.match(refused.said, /HTTP 403/);
});

test('offline, against a root you hold, and a rehearsal network needs its contract', async () => {
  const never = async () => { throw new Error('the chain must not be asked'); };
  assert.equal((await run([REAL, '--root', ROOT], never)).code, 0);
  assert.equal((await run([REAL, '--root', '00'.repeat(32)], never)).code, 1);
  assert.equal((await run([EXAMPLE, '--offline'], never)).code, 0);
  assert.equal((await run([EXAMPLE], never)).code, 2);
});

test('each tampered step is invalid', async () => {
  const cases = [
    (p) => { p.row.close_price = '83911.9'; },
    (p) => { p.row.close_price = '83911.9'; p.canonical = p.canonical.replace('83911.8', '83911.9'); },
    (p) => { p.path[3] = '0'.repeat(64); },
    (p) => { p.index += 1; },
    (p) => { p.partition.leaf = '1'.repeat(64); },
    (p) => { p.day_root = '2'.repeat(64); },
  ];
  for (const change of cases) {
    const { code, said } = await run([tampered(change), '--offline']);
    assert.equal(code, 1, said);
    assert.match(said, /✗ invalid/);
  }
});

test('the key of a revision is ten digits (ADR-036)', () => {
  assert.equal(chainKey('2026-09-30'), 20260930);
  assert.equal(chainKey('2026-10-01', 1), 2026100101);
});
