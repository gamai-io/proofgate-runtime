import unittest

from proofgate_runtime.claims import check, evaluate, verify


class ClaimTests(unittest.TestCase):
    def test_bhs_money(self):
        out = evaluate({"text": "invoice", "predicate": "eq_num",
                        "observed": "2.400,00", "expected": "2400,00"})
        self.assertEqual(out["status"], "confirmed", out)

    def test_high_precision_money(self):
        out = evaluate({"text": "big", "predicate": "eq_num",
                        "observed": "1.234.567,89", "expected": "1234567,89"})
        self.assertEqual(out["status"], "confirmed", out)

    def test_fail_closed_missing(self):
        out = evaluate({"text": "missing", "predicate": "eq_num", "expected": 1})
        self.assertEqual(out["status"], "unverified", out)

    def test_refuted_wins(self):
        report = check([
            {"text": "ok", "predicate": "eq_num", "observed": 4, "expected": 4},
            {"text": "bad", "predicate": "eq_num", "observed": 4, "expected": 5},
            {"text": "unknown", "predicate": "nope", "observed": 1, "expected": 1},
        ])
        self.assertEqual(report["status"], "refuted")
        self.assertEqual(report["counts"], {"confirmed": 1, "refuted": 1, "unverified": 1})

    def test_tamper_detection(self):
        report = check([{"text": "ok", "predicate": "eq_num", "observed": 1, "expected": 1}])
        self.assertTrue(verify(report)["ok"])
        report["claims"][0]["observed"] = 2
        self.assertFalse(verify(report)["ok"])

    def test_reported_hash_mismatch(self):
        report = check([{"text": "ok", "predicate": "eq_num", "observed": 1, "expected": 1}],
                       reported_hash="0" * 64)
        self.assertEqual(report["status"], "unverified")
        self.assertTrue(report.get("tampered"))


if __name__ == "__main__":
    unittest.main()
