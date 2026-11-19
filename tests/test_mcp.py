import json
import os
import unittest
from unittest import mock

from proofgate_runtime.mcp_server import TOOLS, handle
from proofgate_runtime.receipts import verify_receipt


class McpTests(unittest.TestCase):
    def test_initialize(self):
        out = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(out["result"]["serverInfo"]["name"], "proofgate-runtime")

    def test_tools_list(self):
        out = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(len(out["result"]["tools"]), len(TOOLS))

    def test_verify_claims(self):
        out = handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "verify_claims", "arguments": {"claims": [
                {"text": "m", "predicate": "eq_num", "observed": "2.400,00", "expected": "2400,00"}
            ]}}})
        payload = json.loads(out["result"]["content"][0]["text"])
        self.assertEqual(payload["counts"]["confirmed"], 1)

    def test_notification_no_response(self):
        out = handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        self.assertIsNone(out)

    def test_unknown_method(self):
        out = handle({"jsonrpc": "2.0", "id": 4, "method": "nope"})
        self.assertEqual(out["error"]["code"], -32601)

    def test_unsigned_receipt_warning_is_hashed(self):
        with mock.patch.dict(os.environ, {"PROOFGATE_HMAC_KEY": ""}):
            out = handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
                "name": "make_receipt", "arguments": {"intent": {"op": "x"},
                                                      "result": {"ok": True}}}})
        rec = json.loads(out["result"]["content"][0]["text"])
        self.assertIn("_warning", rec)
        check = verify_receipt(rec, require_signature=False)
        self.assertTrue(check["valid"], check)


if __name__ == "__main__":
    unittest.main()
