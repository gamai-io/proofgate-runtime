import contextlib
import io
import json
import os
import tempfile
import unittest

from proofgate_runtime import claims


class VerifyExitTests(unittest.TestCase):
    def _write(self, obj):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        self.addCleanup(os.unlink, path)
        return path

    def _run(self, path):
        with contextlib.redirect_stdout(io.StringIO()):
            return claims.main(["proofgate.py", "verify", path])

    def test_verify_accepts_intact_report(self):
        report = claims.check([
            {"text": "ok", "predicate": "eq_num", "observed": 1, "expected": 1}
        ])
        self.assertEqual(self._run(self._write(report)), 0)

    def test_verify_rejects_tampered_report(self):
        report = claims.check([
            {"text": "ok", "predicate": "eq_num", "observed": 1, "expected": 1}
        ])
        report["claims"][0]["observed"] = 2
        self.assertEqual(self._run(self._write(report)), 1)


if __name__ == "__main__":
    unittest.main()
