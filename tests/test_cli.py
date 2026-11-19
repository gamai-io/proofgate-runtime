import contextlib
import io
import json
import os
import tempfile
import unittest

from proofgate_runtime import cli


class CliTests(unittest.TestCase):
    def _write(self, obj):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        self.addCleanup(os.unlink, path)
        return path

    def test_verify_claims_passes_keyword_reported_hash(self):
        path = self._write({"claims": [
            {"text": "2+2", "predicate": "eq_num", "observed": 4, "expected": 4}
        ]})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["verify-claims", path])
        self.assertEqual(rc, 0)
        report = json.loads(buf.getvalue())
        self.assertEqual(report["status"], "confirmed")
        self.assertEqual(report["counts"]["confirmed"], 1)

    def test_verify_claims_tampered_hash_is_nonzero(self):
        path = self._write({"claims": [
            {"text": "2+2", "predicate": "eq_num", "observed": 4, "expected": 4}
        ]})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["verify-claims", path, "--reported-hash", "0" * 64])
        self.assertEqual(rc, 1)
        report = json.loads(buf.getvalue())
        self.assertTrue(report["tampered"])
        self.assertFalse(report["ok"])


if __name__ == "__main__":
    unittest.main()
