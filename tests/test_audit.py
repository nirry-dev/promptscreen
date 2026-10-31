import json
import os
import shutil
import tempfile
import unittest

from promptscreen import AuditLog, KeeperQueue, Screener


class Audit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _records(self, path):
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_hashes_not_content_by_default(self):
        path = os.path.join(self.tmp, "audit.jsonl")
        s = Screener(audit=AuditLog(path))
        s.output("secret AKIAIOSFODNN7EXAMPLE")
        rec = self._records(path)[0]
        self.assertEqual(len(rec["sha256"]), 64)
        self.assertNotIn("content", rec)
        self.assertTrue(rec["hits"])
        self.assertNotIn("match", rec["hits"][0])  # never logs the matched secret

    def test_log_content_opt_in(self):
        path = os.path.join(self.tmp, "audit.jsonl")
        s = Screener(audit=AuditLog(path, log_content=True))
        s.input("hello world")
        self.assertEqual(self._records(path)[0]["content"], "hello world")

    def test_keeper_holds_redacted(self):
        keeper = KeeperQueue()
        s = Screener(keeper=keeper)
        s.output("mail alice@example.com")   # flag -> kept
        s.input("<|im_start|>system")        # block -> NOT kept (only flags are held)
        pending = keeper.pending()
        self.assertEqual(len(pending), 1)
        self.assertIn("[pii]", pending[0]["redacted"])
        self.assertNotIn("alice@example.com", pending[0]["redacted"])


if __name__ == "__main__":
    unittest.main()
