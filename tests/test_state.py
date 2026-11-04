import os
import tempfile
import unittest

from ad_whitelist_bot import state
from ad_whitelist_bot.config import ANTIAD, AWAVENUE


def mk_source(kind="issue-only", repo=ANTIAD, **kw):
    base = {"repo": repo, "kind": kind, "issues": [{"n": 1, "repo": repo}]}
    base.update(kw)
    return base


class MergeDomainTest(unittest.TestCase):
    def setUp(self):
        self.st = state.empty_state()

    def test_get_or_create_and_append(self):
        rec = state.merge_domain(self.st, "a.com", mk_source())
        self.assertEqual(rec["status"], "active")
        self.assertEqual(len(rec["sources"]), 1)
        state.merge_domain(self.st, "a.com", mk_source())
        self.assertEqual(len(rec["sources"]), 1)  # identical source deduped

    def test_pending_flip_guard_for_approved(self):
        # audit fix: a human-approved domain must never be demoted to active
        rec = state.merge_domain(self.st, "b.com", mk_source())
        rec["status"] = "pending"
        rec["approved_by"] = "manual_overrides"
        state.merge_domain(self.st, "b.com", mk_source(action="reconfirmed"))
        self.assertEqual(rec["status"], "pending",
                         "approved domain must never be auto-activated")
        # ...but un-approved pending domains flip back to active on new evidence
        rec2 = state.merge_domain(self.st, "c.com", mk_source())
        rec2["status"] = "pending"
        state.merge_domain(self.st, "c.com", mk_source(action="x2"))
        self.assertEqual(rec2["status"], "active")


class MergeRecordsTest(unittest.TestCase):
    def setUp(self):
        self.st = state.empty_state()

    def test_new_domain_detection(self):
        new = state.merge_records(self.st, {"a.com": {"sources": [mk_source()]}})
        self.assertEqual(new, ["a.com"])
        new = state.merge_records(self.st, {"a.com": {"sources": [mk_source()]}})
        self.assertEqual(new, [])
        new = state.merge_records(self.st, {"a.com": {"sources": [mk_source(action="new")]}})
        self.assertEqual(new, [])  # domain existed; only source appended


class OverridesTest(unittest.TestCase):
    def setUp(self):
        self.st = state.empty_state()
        self._orig = state.config.DATA_DIR
        self.tmp = tempfile.TemporaryDirectory()
        state.config.DATA_DIR = self.tmp.name

    def tearDown(self):
        state.config.DATA_DIR = self._orig
        self.tmp.cleanup()

    def write_overrides(self, obj):
        import json
        with open(os.path.join(self.tmp.name, "manual_overrides.json"), "w",
                  encoding="utf-8") as f:
            json.dump(obj, f)

    def test_approve_creates_and_promotes(self):
        self.write_overrides({"approve": ["x.com"], "deny": []})
        approved = state.apply_overrides(self.st)
        self.assertEqual(approved, ["x.com"])
        self.assertEqual(self.st["domains"]["x.com"]["status"], "active")
        self.assertEqual(self.st["domains"]["x.com"]["approved_by"], "manual_overrides")

    def test_deny_is_sticky(self):
        state.merge_domain(self.st, "y.com", mk_source())
        self.write_overrides({"approve": [], "deny": ["y.com"]})
        state.apply_overrides(self.st)
        self.assertEqual(self.st["domains"]["y.com"]["status"], "rejected")
        # a later scan appending sources must not reactivate it
        state.merge_domain(self.st, "y.com", mk_source(action="again"))
        self.assertEqual(self.st["domains"]["y.com"]["status"], "rejected")


class SaveLoadTest(unittest.TestCase):
    def test_roundtrip_and_normalization(self):
        st = state.empty_state()
        state.merge_domain(st, "a.com", mk_source())
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            state.save(st, path)
            st2 = state.load(path)
        self.assertIn("a.com", st2["domains"])
        self.assertIn(ANTIAD, st2["issues"])
        self.assertIn(AWAVENUE, st2["issues"])

    def test_load_missing_file(self):
        self.assertEqual(state.load("/nonexistent/path.json")["domains"], {})


if __name__ == "__main__":
    unittest.main()
