# debyko/verify

Check, without trusting DEBYKO, that a row of DEBYKO's stored market-data history is under the Merkle root posted for its UTC day on Base.

One file, standard library only: `verify.py` (Python 3.9+) or `verify.mjs` (Node 18+). Each reads the proof's JSON, recomputes every SHA-256 from
the row to the day's root, reads that day's root from the `DebykoAnchor` contract through a public Base RPC, and prints ✓ or ✗ with exit code 0 or 1.

**The anchor proves the data did not change after the anchor time; it proves nothing about its correctness at collection.**

## Use

```sh
# 1. a proof: any stored row, by venue, symbol, layer and its own time (no key, no account; 30 a minute per address)
curl -s "https://api.debyko.com/v2/anchors/proof?venue=BINANCE-USDM&symbol=BTCUSDT&layer=candles&at=2026-09-30T12:00:00Z&tie=trade" > proof.json

# 2. check it against the chain
curl -sO https://raw.githubusercontent.com/debyko/verify/main/verify.py
python3 verify.py proof.json
```

```
✓ the canonical text is the row (RFC 8785)
✓ SHA-256(0x00 || text) is the leaf hash d81ac227728ac226...
✓ the path (21 nodes, leaf 1434993 of 1612960) leads to the partition root bed16e34d3923e60...
✓ the partition's leaf is candle's table, day, rows, root and schema version
✓ the partition path (4 nodes, leaf 0 of 9) leads to the day root 793d6b654abc9df5...
✓ the day root is 793d6b654abc9df5253cfd33d8e8d2459018880f9353ef3294d8b4607f6de60a (roots(20260930) of 0x0AF8259DBfC613825718d4d49A05F9F6fdA15086 via https://mainnet.base.org)
✓ valid: this row is under the root anchored for 2026-09-30
```

| Option | |
|---|---|
| `--rpc URL` | another public Base RPC (default `https://mainnet.base.org`; others: `https://base-rpc.publicnode.com`, `https://base.drpc.org`) |
| `--contract ADDRESS` | another contract (default: DebykoAnchor on Base mainnet, below) |
| `--root HEX` | compare with a root you already hold; nothing is fetched |
| `--offline` | only check that the proof leads to the day root it states |
| `-` as the file | read the proof from standard input |

Exit codes: `0` valid, `1` invalid (the failing step is named), `2` the chain could not be asked or the input is not a proof.

The Node version takes the same arguments: `node verify.mjs proof.json`.

Without any tool: `cast call 0x0AF8259DBfC613825718d4d49A05F9F6fdA15086 "roots(uint32)(bytes32)" 20260930 --rpc-url https://mainnet.base.org` prints the root of 2026-09-30.
In a browser: [debyko.com/anchors/verify](https://debyko.com/anchors/verify). Every anchored day: [debyko.com/anchors](https://debyko.com/anchors/).

## What is checked

1. `canonical` is the RFC 8785 text of `row` (members sorted, no whitespace; every number is a string).
2. The leaf is `SHA-256(0x00 ‖ canonical)` and equals `leaf_hash`.
3. `path` takes the leaf (leaf `index` of `rows`) to `partition.root` (RFC 9162 §2.1.3.2; a node is `SHA-256(0x01 ‖ left ‖ right)`).
4. The partition's leaf is `SHA-256(0x00 ‖ {"day","root","rows","schema_version","table"})` and equals `partition.leaf`.
5. `partition.path` takes it (leaf `partition.index` of `partition.count`) to `day_root`.
6. The contract holds `day_root` under the day's key: `roots(uint32)`, selector `0x081dc681`, key `yyyymmdd` (a correction, if one is ever made, is revision `r` under `yyyymmdd × 100 + r`).

The contract: `DebykoAnchor` on Base mainnet (chain 8453) at
[`0x0AF8259DBfC613825718d4d49A05F9F6fdA15086`](https://basescan.org/address/0x0AF8259DBfC613825718d4d49A05F9F6fdA15086#code), source verified on BaseScan.
The verifier reads the root from that address, not from the one a proof names. The method in full: [docs.debyko.com/attest/verify](https://docs.debyko.com/attest/verify/).

## Tests

```sh
python3 -m unittest discover -s tests
node --test tests/verify.test.mjs
```

The tests use recorded proofs (`tests/fixtures`: a real proof of a BTCUSDT 1-minute candle of 2026-09-30, and the documented example) and a fake chain;
they make no network call.

## License

MIT, © 2026 MB Debyko.
