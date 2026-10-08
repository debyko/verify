#!/usr/bin/env node
// Verify a DEBYKO anchor proof against the root posted on Base. Node 18 or later, standard library only; the same checks and options as verify.py.
//
//   node verify.mjs proof.json                 reads the day's root from the DebykoAnchor contract on Base mainnet
//   node verify.mjs proof.json --rpc URL       ... through another public Base RPC
//   node verify.mjs proof.json --root HEX      compares with a root you hold, no network
//   node verify.mjs proof.json --offline       checks only that the proof leads to the day root it states
//
// Exit 0: valid. Exit 1: invalid. Exit 2: the chain could not be asked, or the input is not a proof.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const VERSION = '1.0.0';
export const MAINNET_CONTRACT = '0x0AF8259DBfC613825718d4d49A05F9F6fdA15086';
export const DEFAULT_RPC = 'https://mainnet.base.org';
const USER_AGENT = `debyko-verify/${VERSION} (+https://github.com/debyko/verify)`;

const h = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();

/** RFC 8785 for what an anchored row holds: members sorted by UTF-16 code units, no whitespace. */
export const canonicalOf = (value) => (value !== null && typeof value === 'object'
  ? '{' + Object.keys(value).sort().map((k) => JSON.stringify(k) + ':' + canonicalOf(value[k])).join(',') + '}'
  : JSON.stringify(value));

/** RFC 9162 §2.1.3.2: the root an audit path takes `leaf` (index `index` of `size`) to; an empty buffer when the path does not fit. */
export function walk(leaf, index, size, path) {
  let fn = BigInt(index), sn = BigInt(size) - 1n, r = leaf;
  for (const p of path.map((x) => Buffer.from(x, 'hex'))) {
    if (sn === 0n) return Buffer.alloc(0);
    if ((fn & 1n) === 1n || fn === sn) {
      r = h(Buffer.from([1]), p, r);
      while ((fn & 1n) === 0n && fn !== 0n) { fn >>= 1n; sn >>= 1n; }
    } else {
      r = h(Buffer.from([1]), r, p);
    }
    fn >>= 1n; sn >>= 1n;
  }
  return sn === 0n ? r : Buffer.alloc(0);
}

export const chainKey = (day, revision = 0) => (revision ? Number(day.replaceAll('-', '')) * 100 + Number(revision) : Number(day.replaceAll('-', '')));

export const rootsCalldata = (key) => '0x081dc681' + BigInt(key).toString(16).padStart(64, '0');

/** roots(key) of the contract: the 64 hex digits, or null when nothing is stored. Throws an Error naming the RPC. */
export async function chainRoot(rpc, contract, key, fetcher = fetch) {
  let answer;
  try {
    const response = await fetcher(rpc, {
      method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': USER_AGENT },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: contract, data: rootsCalldata(key) }, 'latest'] }),
      signal: AbortSignal.timeout(20000),
    });
    if (!response.ok) throw new Error(`${rpc} answered HTTP ${response.status}`);
    answer = await response.json();
  } catch (e) {
    throw new Error(e.message.startsWith(rpc) ? e.message : `${rpc} could not be asked: ${e.cause?.message ?? e.message}`);
  }
  if (typeof answer?.result !== 'string') throw new Error(`${rpc} answered ${JSON.stringify(answer?.error ?? answer).slice(0, 200)}`);
  const word = answer.result.replace(/^0x/, '').toLowerCase();
  if (word.length !== 64) throw new Error(`${rpc} answered ${word.length / 2} bytes, not 32`);
  return /^0+$/.test(word) ? null : word;
}

/** Every check of the proof, in order, as [name, ok]; stops at the first that fails. */
export function steps(proof) {
  const out = [];
  const step = (name, ok) => { out.push([name, ok]); return ok; };
  const { row, canonical, partition } = proof;
  if (!step('the canonical text is the row (RFC 8785)', canonicalOf(row) === canonical)) return out;
  const leaf = h(Buffer.from([0]), Buffer.from(canonical));
  if (!step(`SHA-256(0x00 || text) is the leaf hash ${proof.leaf_hash.slice(0, 16)}...`, leaf.toString('hex') === proof.leaf_hash)) return out;
  if (!step(`the path (${proof.path.length} nodes, leaf ${proof.index} of ${proof.rows}) leads to the partition root ${partition.root.slice(0, 16)}...`,
    walk(leaf, proof.index, proof.rows, proof.path).toString('hex') === partition.root)) return out;
  const text = canonicalOf({ day: proof.day, root: partition.root, rows: proof.rows, schema_version: proof.schema_version, table: proof.table });
  const partitionLeaf = h(Buffer.from([0]), Buffer.from(text));
  if (!step(`the partition's leaf is ${proof.table}'s table, day, rows, root and schema version`, partitionLeaf.toString('hex') === partition.leaf)) return out;
  step(`the partition path (${partition.path.length} nodes, leaf ${partition.index} of ${partition.count}) leads to the day root ${proof.day_root.slice(0, 16)}...`,
    walk(partitionLeaf, partition.index, partition.count, partition.path).toString('hex') === proof.day_root);
  return out;
}

export async function main(argv, { fetcher = fetch, say = console.log, input = () => readFileSync(0, 'utf8') } = {}) {
  const flag = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : undefined);
  const file = argv[0];
  if (!file) { say('usage: node verify.mjs proof.json [--rpc URL] [--contract ADDRESS] [--root HEX] [--offline]'); return 2; }
  let proof, checks;
  try {
    proof = JSON.parse(file === '-' ? input() : readFileSync(file, 'utf8'));
    if (proof?.errors) { say('not a proof: ' + JSON.stringify(proof.errors).slice(0, 300)); return 2; }
    checks = steps(proof);
  } catch (e) {
    say(`not a proof: ${e.message}`);
    return 2;
  }
  for (const [name, ok] of checks) say(`${ok ? '✓' : '✗'} ${name}`);
  const failed = checks.find(([, ok]) => !ok);
  if (failed) { say(`✗ invalid: ${failed[0]}`); return 1; }
  const given = flag('--root');
  if (argv.includes('--offline') && given === undefined) { say('✓ valid against the day root the proof states (the chain was not asked: --offline)'); return 0; }
  let held, source;
  if (given !== undefined) {
    held = given.toLowerCase().replace(/^0x/, '');
    source = 'the root you gave';
  } else {
    const contract = flag('--contract') ?? (proof.network === 'base' ? MAINNET_CONTRACT : undefined);
    if (!contract) { say(`the proof is about ${proof.network}: name its contract with --contract (a rehearsal network binds nobody)`); return 2; }
    const named = proof.anchor?.contract;
    if (named && named.toLowerCase() !== contract.toLowerCase()) say(`note: the proof names the contract ${named}; the root is read from ${contract}`);
    const rpc = flag('--rpc') ?? DEFAULT_RPC;
    const key = chainKey(proof.day, proof.revision ?? 0);
    try {
      held = await chainRoot(rpc, contract, key, fetcher);
    } catch (e) {
      say(`could not read the root from the chain: ${e.message}; another public Base RPC can be given with --rpc`);
      return 2;
    }
    source = `roots(${key}) of ${contract} via ${rpc}`;
    if (held === null) { say(`✗ invalid: nothing is stored for ${proof.day} (${source})`); return 1; }
  }
  if (held !== proof.day_root) { say(`✗ invalid: the day root is not ${held} (${source})`); return 1; }
  say(`✓ the day root is ${held} (${source})`);
  say(`✓ valid: this row is under the root anchored for ${proof.day}`);
  return 0;
}

if (process.argv[1] && import.meta.url === new URL(process.argv[1], 'file:').href) {
  process.exit(await main(process.argv.slice(2)));
}
