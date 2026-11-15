import unittest

from ad_whitelist_bot import pipeline, state
from ad_whitelist_bot.config import ANTIAD, AWAVENUE


class PhpRemovalTest(unittest.TestCase):
    def test_demote_only_when_no_backing(self):
        st = state.empty_state()
        rec = state.merge_domain(st, "php-only.com", {
            "repo": ANTIAD, "kind": "whitelist-php", "value": 0,
            "issues": [{"n": 1, "repo": ANTIAD}]})
        dual = state.merge_domain(st, "dual.com", {
            "repo": ANTIAD, "kind": "whitelist-php", "value": 0,
            "issues": [{"n": 2, "repo": ANTIAD}]})
        state.merge_domain(st, "dual.com", {
            "repo": AWAVENUE, "kind": "issue-confirmed",
            "issues": [{"n": 9, "repo": AWAVENUE}]})
        demoted = pipeline._annotate_php_removals(
            st, ["php-only.com", "dual.com", "ghost.com"], "2026-11-15")
        self.assertEqual(demoted, ["php-only.com"])  # dual 有 AWAvenue 背书不降
        self.assertEqual(rec["status"], "pending")
        self.assertEqual(dual["status"], "active")
        for s in rec["sources"]:
            if s.get("kind") == "whitelist-php":
                self.assertEqual(s.get("php_removed"), "2026-11-15")

    def test_missing_domain_ignored(self):
        st = state.empty_state()
        self.assertEqual(
            pipeline._annotate_php_removals(st, ["ghost.com"], "2026-11-15"), [])


class SubstantiveTest(unittest.TestCase):
    @staticmethod
    def _st():
        st = state.empty_state()
        state.merge_domain(st, "a.com", {
            "repo": ANTIAD, "kind": "whitelist-php", "value": 0,
            "issues": [{"n": 1, "repo": ANTIAD}]})
        return st

    def test_status_flip_detected(self):
        st = self._st()
        before = pipeline._snapshot(st)
        st["domains"]["a.com"]["status"] = "conflict"
        self.assertTrue(pipeline._substantive(before, pipeline._snapshot(st)))

    def test_source_edit_detected_without_domain_change(self):
        st = self._st()
        before = pipeline._snapshot(st)
        st["domains"]["a.com"]["sources"][0]["comment"] = "新注释"  # 溯源文本变
        self.assertTrue(pipeline._substantive(before, pipeline._snapshot(st)))

    def test_noref_change_detected(self):
        st = self._st()
        before = pipeline._snapshot(st)
        st["whitelist_php_noref"]["b.com"] = "无引用条目"
        self.assertTrue(pipeline._substantive(before, pipeline._snapshot(st)))

    def test_pending_change_detected(self):
        st = self._st()
        before = pipeline._snapshot(st)
        state.merge_domain(st, "p.com", {"repo": ANTIAD, "kind": "issue-only",
                                         "issues": [{"n": 3, "repo": ANTIAD}]})
        st["domains"]["p.com"]["status"] = "pending"
        self.assertTrue(pipeline._substantive(before, pipeline._snapshot(st)))

    def test_no_change_is_not_substantive(self):
        st = self._st()
        before = pipeline._snapshot(st)
        st["generated_at"] = "2099-01-01T00:00:00Z"  # 时间戳不算实质变更
        st["checkpoints"][ANTIAD] = "2099-01-01T00:00:00Z"
        self.assertFalse(pipeline._substantive(before, pipeline._snapshot(st)))


if __name__ == "__main__":
    unittest.main()
