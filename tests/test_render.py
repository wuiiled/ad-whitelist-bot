import os
import tempfile
import unittest

from ad_whitelist_bot import render, state
from ad_whitelist_bot.config import ANTIAD, AWAVENUE


def build_st():
    st = state.empty_state()
    # anti-AD php-sourced with comment + issue ref
    state.merge_domain(st, "php.com", {
        "repo": ANTIAD, "kind": "whitelist-php", "value": 0,
        "comment": "修复同花顺的tips异常 #156", "issues": [{"n": 156, "repo": ANTIAD}]})
    # AWAvenue issue-confirmed with issue record title
    state.merge_domain(st, "aw.com", {
        "repo": AWAVENUE, "kind": "issue-confirmed", "action": "已移除",
        "note": "抖音人脸识别登录", "issues": [{"n": 113, "repo": AWAVENUE}]})
    st["issues"][AWAVENUE]["113"] = {"status": "done", "locked": True,
                                     "title": "[BUG] <问题标题>抖音登录账号时人脸识别加载失败"}
    # manual approval carrying issue provenance
    state.merge_domain(st, "man.com", {
        "repo": "manual", "kind": "manual", "action": "OpenPGP公钥服务器被拦(#720)",
        "issues": [{"n": 720, "repo": ANTIAD}]})
    return st


class AnnotatedListTest(unittest.TestCase):
    def test_format(self):
        st = build_st()
        with tempfile.TemporaryDirectory() as tmp:
            lines = render.render_annotated_list(st, tmp)
            content = open(os.path.join(tmp, "whitelist_annotated.txt"),
                           encoding="utf-8").read()
        by_domain = dict(l.split("  # ", 1) for l in lines)
        # php comment wins when the issue has no scanned record
        self.assertIn("anti-AD #156(修复同花顺的tips异常;php白名单)",
                      by_domain["php.com"])
        # locked records carry placeholder titles -> seed note is used instead
        self.assertIn("AWAvenue #113(抖音人脸识别登录;已移除)",
                      by_domain["aw.com"])
        self.assertIn("人工 #720(OpenPGP公钥服务器被拦(#720);人工批准)",
                      by_domain["man.com"])
        self.assertIn("Total: 3", content)
        # no template noise leaks into comments
        self.assertNotIn("[BUG]", content)

    def test_rejected_sources_skipped(self):
        st = build_st()
        rec = state.merge_domain(st, "x.com", {
            "repo": AWAVENUE, "kind": "rejected", "action": "rejected",
            "note": "拒收", "issues": [{"n": 1, "repo": AWAVENUE}]})
        rec["status"] = "rejected"
        with tempfile.TemporaryDirectory() as tmp:
            lines = render.render_annotated_list(st, tmp)
        self.assertEqual(len(lines), 3)


class DictOverridesTest(unittest.TestCase):
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

    def test_dict_entry_creates_domain_with_issues(self):
        self.write_overrides({"approve": [
            {"domain": "k.org", "note": "公钥服务器被拦(#720)",
             "issues": [{"n": 720, "repo": ANTIAD}]}],
            "deny": []})
        approved = state.apply_overrides(self.st)
        self.assertEqual(approved, ["k.org"])
        rec = self.st["domains"]["k.org"]
        self.assertEqual(rec["status"], "active")
        self.assertEqual(rec["sources"][0]["issues"][0]["n"], 720)

    def test_dict_entry_attaches_issues_to_existing(self):
        state.merge_domain(self.st, "p.org", {
            "repo": ANTIAD, "kind": "issue-only", "action": "确认",
            "issues": []})
        self.st["domains"]["p.org"]["status"] = "pending"
        self.write_overrides({"approve": [
            {"domain": "p.org", "note": "核实", "issues": [{"n": 5, "repo": ANTIAD}]}],
            "deny": []})
        approved = state.apply_overrides(self.st)
        self.assertEqual(approved, ["p.org"])
        rec = self.st["domains"]["p.org"]
        self.assertEqual(rec["status"], "active")
        self.assertTrue(any(s.get("issues") and s["issues"][0]["n"] == 5
                            for s in rec["sources"]))


if __name__ == "__main__":
    unittest.main()
