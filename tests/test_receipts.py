import unittest

from proofgate_runtime.receipts import make_receipt, verify_receipt, canonical_json


class ReceiptTests(unittest.TestCase):
    def test_unsigned_receipt(self):
        r = make_receipt({"op": "x"}, {"ok": True})
        out = verify_receipt(r)
        self.assertTrue(out["valid"], out)
        self.assertFalse(out["signed"])

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

    def test_require_signature(self):
        r = make_receipt({"op": "x"}, {"ok": True})
        out = verify_receipt(r, require_signature=True)
        self.assertFalse(out["valid"])
        self.assertIn("E_UNSIGNED", out["errors"])

    def test_canonical_json_stable(self):
        self.assertEqual(canonical_json({"b": 1, "a": 2}), '{"a":2,"b":1}')


if __name__ == "__main__":
    unittest.main()
