#!/usr/bin/env python3
"""Verify a DEBYKO anchor proof against the root posted on Base. Python 3.9+, standard library only.

    python3 verify.py proof.json                  reads the day's root from the DebykoAnchor contract on Base mainnet
    python3 verify.py proof.json --rpc URL        ... through another public Base RPC (https://base-rpc.publicnode.com, https://base.drpc.org)
    python3 verify.py proof.json --root HEX       compares with a root you hold, no network at all
    python3 verify.py proof.json --offline        checks only that the proof leads to the day root it states
    curl -s "https://api.debyko.com/v2/anchors/proof?..." | python3 verify.py -

A proof is the JSON of GET https://api.debyko.com/v2/anchors/proof (no key needed) or of the MCP tool anchor_proof. Prints every step with a
check mark and the verdict. Exit 0: valid. Exit 1: invalid (the step that failed is named). Exit 2: the chain could not be asked, or the input is
not a proof. The anchor proves the data did not change after the anchor time; it proves nothing about its correctness at collection.
"""
import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request

__version__ = "1.0.0"

# DebykoAnchor on Base mainnet (chain 8453), source verified on BaseScan; published at https://docs.debyko.com/attest/verify/
MAINNET_CONTRACT = "0x0AF8259DBfC613825718d4d49A05F9F6fdA15086"
DEFAULT_RPC = "https://mainnet.base.org"
# keccak256("roots(uint32)")[0:4]
ROOTS_SELECTOR = "081dc681"
# an explicit User-Agent: Base's public RPC answers 403 to Python's default one
USER_AGENT = "debyko-verify/" + __version__ + " (+https://github.com/debyko/verify)"


def h(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def canonical_of(row):
    """RFC 8785 for what an anchored row holds (strings, booleans, null): sorted members, no whitespace, strings as JSON writes them."""
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def walk(leaf, index, size, path):
    """RFC 9162 section 2.1.3.2: the root an audit path takes `leaf` (index `index` of `size`) to; b"" when the path does not fit the size."""
    fn, sn, r = index, size - 1, leaf
    for p in map(bytes.fromhex, path):
        if sn == 0:
            return b""
        if fn & 1 or fn == sn:
            r = h(b"\x01", p, r)
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            r = h(b"\x01", r, p)
        fn, sn = fn >> 1, sn >> 1
    return r if sn == 0 else b""


def chain_key(day, revision=0):
    """The key a root is stored under in the contract: yyyymmdd for the day as anchored, yyyymmdd * 100 + r for its revision r (ADR-036)."""
    base = int(day.replace("-", ""))
    return base if not revision else base * 100 + int(revision)


def roots_calldata(key):
    return "0x" + ROOTS_SELECTOR + format(key, "064x")


class ChainError(Exception):
    pass


def chain_root(rpc, contract, key, opener=urllib.request.urlopen):
    """roots(key) of the contract via eth_call: the 64 hex digits, or None when nothing is stored for the key."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": contract, "data": roots_calldata(key)}, "latest"]}).encode()
    request = urllib.request.Request(rpc, body, {"content-type": "application/json", "user-agent": USER_AGENT})
    try:
        with opener(request, timeout=20) as response:
            answer = json.load(response)
    except urllib.error.HTTPError as e:
        raise ChainError("{} answered HTTP {}".format(rpc, e.code))
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise ChainError("{} could not be asked: {}".format(rpc, getattr(e, "reason", e)))
    result = answer.get("result") if isinstance(answer, dict) else None
    if not isinstance(result, str):
        raise ChainError("{} answered {}".format(rpc, json.dumps(answer.get("error", answer) if isinstance(answer, dict) else answer)[:200]))
    word = result[2:].lower() if result.startswith("0x") else result.lower()
    if len(word) != 64:
        raise ChainError("{} answered {} bytes, not 32: is {} the DebykoAnchor contract?".format(rpc, len(word) // 2, contract))
    return None if set(word) == {"0"} else word


def steps(proof):
    """Every check of the proof, in order, as (name, ok); stops at the first that fails."""
    out = []

    def step(name, ok):
        out.append((name, ok))
        return ok

    row, canonical, partition = proof["row"], proof["canonical"], proof["partition"]
    # 1. the text that is hashed is the canonical form of the row
    if not step("the canonical text is the row (RFC 8785)", canonical_of(row) == canonical):
        return out
    # 2. its leaf
    leaf = h(b"\x00", canonical.encode())
    if not step("SHA-256(0x00 || text) is the leaf hash " + proof["leaf_hash"][:16] + "...", leaf.hex() == proof["leaf_hash"]):
        return out
    # 3. the path to the partition's root
    if not step("the path ({} nodes, leaf {} of {}) leads to the partition root {}...".format(len(proof["path"]), proof["index"], proof["rows"], partition["root"][:16]),
                walk(leaf, proof["index"], proof["rows"], proof["path"]).hex() == partition["root"]):
        return out
    # 4. the partition's leaf commits to its table, day, size, root and schema version
    text = json.dumps({"day": proof["day"], "root": partition["root"], "rows": proof["rows"], "schema_version": proof["schema_version"], "table": proof["table"]},
                      sort_keys=True, separators=(",", ":"))
    pleaf = h(b"\x00", text.encode())
    if not step("the partition's leaf is " + proof["table"] + "'s table, day, rows, root and schema version", pleaf.hex() == partition["leaf"]):
        return out
    # 5. its path to the day's root
    step("the partition path ({} nodes, leaf {} of {}) leads to the day root {}...".format(len(partition["path"]), partition["index"], partition["count"], proof["day_root"][:16]),
         walk(pleaf, partition["index"], partition["count"], partition["path"]).hex() == proof["day_root"])
    return out


def main(argv=None, opener=urllib.request.urlopen, out=sys.stdout):
    parser = argparse.ArgumentParser(description="Verify a DEBYKO anchor proof against the root posted on Base.")
    parser.add_argument("proof", help="the proof's JSON file, or - for standard input")
    parser.add_argument("--rpc", default=DEFAULT_RPC, help="a public Base RPC (default %(default)s)")
    parser.add_argument("--contract", default=None, help="the DebykoAnchor address (default: the one published for Base mainnet)")
    parser.add_argument("--root", default=None, help="compare with this day root instead of asking the chain")
    parser.add_argument("--offline", action="store_true", help="only check that the proof leads to the day root it states")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    if out is sys.stdout and hasattr(out, "reconfigure"):
        out.reconfigure(errors="replace")  # a console that cannot print a check mark prints "?" rather than fail

    def say(line):
        print(line, file=out)

    try:
        if args.proof == "-":
            proof = json.load(sys.stdin)
        else:
            with open(args.proof, encoding="utf-8") as f:
                proof = json.load(f)
        if "errors" in proof:
            say("not a proof: " + json.dumps(proof["errors"])[:300])
            return 2
        checks = steps(proof)
    except (OSError, ValueError, KeyError, TypeError) as e:
        say("not a proof: {}".format(e))
        return 2
    for name, ok in checks:
        say(("✓ " if ok else "✗ ") + name)
    if not all(ok for _, ok in checks):
        say("✗ invalid: " + next(name for name, ok in checks if not ok))
        return 1

    if args.offline and args.root is None:
        say("✓ valid against the day root the proof states (the chain was not asked: --offline)")
        return 0
    if args.root is not None:
        held, source = args.root.lower()[2:] if args.root.lower().startswith("0x") else args.root.lower(), "the root you gave"
    else:
        network = proof.get("network")
        contract = args.contract or (MAINNET_CONTRACT if network == "base" else None)
        if contract is None:
            say("the proof is about {}: name its contract with --contract (a rehearsal network binds nobody)".format(network))
            return 2
        named = (proof.get("anchor") or {}).get("contract")
        if named and named.lower() != contract.lower():
            say("note: the proof names the contract {}; the root is read from {}".format(named, contract))
        key = chain_key(proof["day"], proof.get("revision", 0))
        try:
            held = chain_root(args.rpc, contract, key, opener)
        except ChainError as e:
            say("could not read the root from the chain: {}; another public Base RPC can be given with --rpc".format(e))
            return 2
        source = "roots({}) of {} via {}".format(key, contract, args.rpc)
        if held is None:
            say("✗ invalid: nothing is stored for {} ({})".format(proof["day"], source))
            return 1
    if held != proof["day_root"]:
        say("✗ invalid: the day root is not {} ({})".format(held, source))
        return 1
    say("✓ the day root is {} ({})".format(held, source))
    say("✓ valid: this row is under the root anchored for " + proof["day"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
