"""Tests of verify.py on recorded proofs. No network: the chain is a fake opener that records the request and answers what the test says."""
import copy
import io
import json
import os
import sys
import unittest
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import verify  # noqa: E402

REAL = os.path.join(HERE, "fixtures", "proof-2026-09-30-candle.json")
EXAMPLE = os.path.join(HERE, "fixtures", "example-proof.json")
ROOT_2026_09_30 = "793d6b654abc9df5253cfd33d8e8d2459018880f9353ef3294d8b4607f6de60a"


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeChain:
    """An eth_call endpoint: answers `word` (or raises `error`), and keeps what it was sent."""

    def __init__(self, word=None, error=None, raw=None):
        self.word, self.error, self.raw, self.requests = word, error, raw, []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        body = self.raw if self.raw is not None else {"jsonrpc": "2.0", "id": 1, "result": "0x" + self.word}
        return FakeResponse(json.dumps(body).encode())


def run(args, chain=None):
    out = io.StringIO()
    code = verify.main(args, opener=chain or FakeChain(word=ROOT_2026_09_30), out=out)
    return code, out.getvalue()


def write(proof, name):
    path = os.path.join(HERE, "fixtures", "_tmp_" + name + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(proof, f)
    return path


class VerifyTests(unittest.TestCase):
    def tearDown(self):
        for name in os.listdir(os.path.join(HERE, "fixtures")):
            if name.startswith("_tmp_"):
                os.remove(os.path.join(HERE, "fixtures", name))

    def test_the_real_proof_of_a_2026_09_30_candle_is_valid_against_the_chain(self):
        chain = FakeChain(word=ROOT_2026_09_30)
        code, said = run([REAL], chain)
        self.assertEqual(code, 0, said)
        self.assertIn("✓ valid", said)
        request = chain.requests[0]
        self.assertEqual(request.full_url, verify.DEFAULT_RPC)
        self.assertTrue(request.get_header("User-agent").startswith("debyko-verify/"))
        call = json.loads(request.data)
        self.assertEqual(call["method"], "eth_call")
        self.assertEqual(call["params"][0]["to"], verify.MAINNET_CONTRACT)
        self.assertEqual(call["params"][0]["data"], "0x081dc681" + format(20260930, "064x"))

    def test_another_rpc_can_be_named(self):
        chain = FakeChain(word=ROOT_2026_09_30)
        code, _ = run([REAL, "--rpc", "https://base-rpc.publicnode.com"], chain)
        self.assertEqual(code, 0)
        self.assertEqual(chain.requests[0].full_url, "https://base-rpc.publicnode.com")

    def test_another_root_on_the_chain_or_none_is_invalid(self):
        code, said = run([REAL], FakeChain(word="ab" * 32))
        self.assertEqual(code, 1)
        self.assertIn("invalid: the day root is not", said)
        code, said = run([REAL], FakeChain(word="0" * 64))
        self.assertEqual(code, 1)
        self.assertIn("nothing is stored", said)

    def test_an_rpc_that_refuses_is_named_with_exit_2(self):
        error = urllib.error.HTTPError(verify.DEFAULT_RPC, 403, "Forbidden", {}, None)
        code, said = run([REAL], FakeChain(error=error))
        self.assertEqual(code, 2)
        self.assertIn("HTTP 403", said)
        self.assertIn("--rpc", said)
        code, said = run([REAL], FakeChain(error=urllib.error.URLError("no route")))
        self.assertEqual(code, 2)
        code, said = run([REAL], FakeChain(raw={"jsonrpc": "2.0", "id": 1, "error": {"message": "execution reverted"}}))
        self.assertEqual(code, 2)
        self.assertIn("execution reverted", said)

    def test_offline_against_a_root_you_hold(self):
        chain = FakeChain(error=AssertionError("the chain must not be asked"))
        self.assertEqual(run([REAL, "--root", ROOT_2026_09_30], chain)[0], 0)
        self.assertEqual(run([REAL, "--root", "0x" + ROOT_2026_09_30.upper()], chain)[0], 0)
        self.assertEqual(run([REAL, "--root", "00" * 32], chain)[0], 1)
        self.assertEqual(run([EXAMPLE, "--offline"], chain)[0], 0)
        self.assertEqual(chain.requests, [])

    def test_a_rehearsal_network_needs_its_contract_named(self):
        code, said = run([EXAMPLE], FakeChain(error=AssertionError("not asked")))
        self.assertEqual(code, 2)
        self.assertIn("--contract", said)

    def test_each_tampered_step_is_invalid_and_named(self):
        real = load(REAL)
        cases = {}
        row = copy.deepcopy(real)
        row["row"]["close_price"] = "83911.9"
        cases["the canonical text is the row"] = row
        both = copy.deepcopy(real)
        both["row"]["close_price"] = "83911.9"
        both["canonical"] = both["canonical"].replace("83911.8", "83911.9")
        cases["is the leaf hash"] = both
        path = copy.deepcopy(real)
        path["path"][3] = "0" * 64
        cases["leads to the partition root"] = path
        index = copy.deepcopy(real)
        index["index"] += 1
        cases["leads to the partition root "] = index
        partition = copy.deepcopy(real)
        partition["partition"]["leaf"] = "1" * 64
        cases["the partition's leaf"] = partition
        day = copy.deepcopy(real)
        day["day_root"] = "2" * 64
        cases["leads to the day root"] = day
        for i, (expected, proof) in enumerate(cases.items()):
            code, said = run([write(proof, str(i)), "--offline"])
            self.assertEqual(code, 1, said)
            self.assertIn("✗ invalid", said)
            self.assertIn(expected.strip(), said.splitlines()[-1])

    def test_an_error_answer_or_garbage_is_not_a_proof(self):
        self.assertEqual(run([write({"errors": [{"code": "ANCHOR_NOT_YET"}]}, "err"), "--offline"])[0], 2)
        self.assertEqual(run([write({"day": "2026-09-30"}, "partial"), "--offline"])[0], 2)

    def test_the_chain_key_of_a_revision_is_ten_digits(self):
        self.assertEqual(verify.chain_key("2026-09-30"), 20260930)
        self.assertEqual(verify.chain_key("2026-10-01", 1), 2026100101)


if __name__ == "__main__":
    unittest.main()
