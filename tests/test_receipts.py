import unittest

from proofgate_runtime.receipts import (make_receipt, verify_receipt,
                                        verify_chain, canonical_json)


class ReceiptTests(unittest.TestCase):
    def test_unsigned_receipt(self):
        r = make_receipt({"op": "x"}, {"ok": True})
        out = verify_receipt(r, require_signature=False)
        self.assertTrue(out["valid"], out)
        self.assertFalse(out["signed"])
        self.assertFalse(verify_receipt(r)["valid"])

    def test_signed_receipt(self):
        r = make_receipt({"op": "x"}, {"ok": True}, key="secret")
        out = verify_receipt(r, key="secret")
        self.assertTrue(out["valid"], out)
        self.assertTrue(out["signed"])

    def test_wrong_key(self):
        r = make_receipt({"op": "x"}, {"ok": True}, key="secret")
        out = verify_receipt(r, key="wrong")
        self.assertFalse(out["valid"])
        self.assertIn("E_SIGNATURE", out["errors"])

    def test_tamper(self):
        r = make_receipt({"op": "x"}, {"ok": True}, key="secret")
        r["result"]["ok"] = False
        out = verify_receipt(r, key="secret")
        self.assertFalse(out["valid"])
        self.assertIn("E_RESULT_DIGEST", out["errors"])

    def test_require_signature_default(self):
        r = make_receipt({"op": "x"}, {"ok": True})
        out = verify_receipt(r)
        self.assertFalse(out["valid"])
        self.assertIn("E_UNSIGNED", out["errors"])

    def test_canonical_json_stable(self):
        self.assertEqual(canonical_json({"b": 1, "a": 2}), '{"a":2,"b":1}')

    def test_make_receipt_writes_prev_hash(self):
        r = make_receipt({"op": "x"}, {"ok": True})
        self.assertEqual(r["prev_hash"], "GENESIS")

    def test_chain_verifies(self):
        r1 = make_receipt({"op": 1}, {"ok": True}, key="secret")
        r2 = make_receipt({"op": 2}, {"ok": True}, key="secret",
                          prev_hash=r1["receipt_hash"])
        out = verify_chain([r1, r2], key="secret")
        self.assertTrue(out["valid"], out)
        self.assertEqual(out["count"], 2)

    def test_chain_detects_break(self):
        r1 = make_receipt({"op": 1}, {"ok": True}, key="secret")
        r2 = make_receipt({"op": 2}, {"ok": True}, key="secret")
        out = verify_chain([r1, r2], key="secret")
        self.assertFalse(out["valid"])
        self.assertIn("E_CHAIN_AT_1", out["errors"])


if __name__ == "__main__":
    unittest.main()
