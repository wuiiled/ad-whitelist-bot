import json
import os
import tempfile
import unittest

from ad_whitelist_bot import pipeline, state
from ad_whitelist_bot.config import ANTIAD, ANUDEEP, AWAVENUE, CATS


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


class ReferralRetirementTest(unittest.TestCase):
    """referral 存活对账: 标记 + 降级 + feed 健康防呆(镜像 php 撤除)。"""

    def test_mark_and_demote_unbacked_active(self):
        st = state.empty_state()
        rec = state.merge_domain(st, "cats-only.com", {
            "repo": CATS, "kind": "referral", "action": "curated"})
        state.merge_domain(st, "backed.com", {
            "repo": CATS, "kind": "referral", "action": "curated"})
        state.merge_domain(st, "backed.com", {
            "repo": ANTIAD, "kind": "whitelist-php", "value": 0,
            "issues": [{"n": 1, "repo": ANTIAD}]})
        live = {CATS: {"backed.com"}}
        demoted = pipeline._annotate_referral_removals(st, live, "2026-11-16")
        self.assertEqual(demoted, ["cats-only.com"])
        self.assertEqual(rec["status"], "pending")
        self.assertEqual(rec.get("demoted_by"), "referral-removal")
        self.assertEqual(rec["sources"][0].get("referral_removed"), "2026-11-16")
        self.assertEqual(st["domains"]["backed.com"]["status"], "active")
        self.assertNotIn("referral_removed",
                         st["domains"]["backed.com"]["sources"][0])

    def test_empty_feed_skips_marking(self):
        # 一轮坏抓取(空文件)不得把整个策展层静默退役
        st = state.empty_state()
        rec = state.merge_domain(st, "cats-only.com", {
            "repo": CATS, "kind": "referral", "action": "curated"})
        live = {CATS: set()}
        pipeline._guard_referral_feeds(st, live)
        self.assertIsNone(live[CATS])
        self.assertEqual(pipeline._annotate_referral_removals(st, live, "2026-11-16"), [])
        self.assertIsNone(rec["sources"][0].get("referral_removed"))
        self.assertEqual(rec["status"], "active")

    def test_collapsed_feed_skips_marking(self):
        st = state.empty_state()
        for i in range(4):
            state.merge_domain(st, f"d{i}.com", {
                "repo": CATS, "kind": "referral", "action": "curated"})
        live = {CATS: {"d0.com"}}  # 1 live vs 4 backed in state -> 收缩异常
        pipeline._guard_referral_feeds(st, live)
        self.assertIsNone(live[CATS])

    def test_healthy_feed_marks_removals(self):
        st = state.empty_state()
        for i in range(4):
            state.merge_domain(st, f"d{i}.com", {
                "repo": CATS, "kind": "referral", "action": "curated"})
        live = {CATS: {"d0.com", "d1.com", "d2.com", "extra.com"}}  # 增不减,健康
        pipeline._guard_referral_feeds(st, live)
        self.assertEqual(live[CATS], {"d0.com", "d1.com", "d2.com", "extra.com"})

    def test_readd_clears_flag_before_merge_no_duplicate(self):
        # 双背书 active 记录(php+cats): cats 删→标记(status 保持 active)→
        # cats 加回→对账层先清标记, merge 字典相等不产生重复 source
        st = state.empty_state()
        rec = state.merge_domain(st, "dual.com", {
            "repo": ANTIAD, "kind": "whitelist-php", "value": 0, "issues": []})
        state.merge_domain(st, "dual.com", {
            "repo": CATS, "kind": "referral", "action": "curated"})
        pipeline._annotate_referral_removals(st, {CATS: set()}, "2026-11-15")
        cats_src = [s for s in rec["sources"] if s["kind"] == "referral"][0]
        self.assertEqual(cats_src.get("referral_removed"), "2026-11-15")
        self.assertEqual(rec["status"], "active")  # php 背书, 不降级
        # 仍缺席: setdefault 保留首次退役日期
        pipeline._annotate_referral_removals(st, {CATS: set()}, "2026-11-16")
        self.assertEqual(cats_src["referral_removed"], "2026-11-15")
        # 恢复: 对账层清标记 → merge 字典相等, 零重复
        pipeline._annotate_referral_removals(st, {CATS: {"dual.com"}}, "2026-11-17")
        self.assertNotIn("referral_removed", cats_src)
        state.merge_referral(st, {"dual.com": {
            "domain": "dual.com",
            "sources": [{"repo": CATS, "kind": "referral", "action": "curated"}]}})
        self.assertEqual([s for s in rec["sources"] if s["kind"] == "referral"],
                         [cats_src])
        self.assertEqual(rec["status"], "active")

    def test_readd_pop_is_per_repo(self):
        # cats+anudeep 双退役降级 pending, 仅 cats 恢复: 只清 cats 标记,
        # anudeep 退役标记保留(不随全量 pop 误清)
        st = state.empty_state()
        rec = state.merge_domain(st, "x.com", {
            "repo": CATS, "kind": "referral", "action": "curated"})
        state.merge_domain(st, "x.com", {
            "repo": ANUDEEP, "kind": "referral", "action": "curated"})
        pipeline._annotate_referral_removals(
            st, {CATS: set(), ANUDEEP: set()}, "2026-11-15")
        self.assertEqual(rec["status"], "pending")
        self.assertEqual(rec.get("demoted_by"), "referral-removal")
        pipeline._annotate_referral_removals(
            st, {CATS: {"x.com"}, ANUDEEP: set()}, "2026-11-16")
        cats_src, anu_src = rec["sources"][0], rec["sources"][1]
        self.assertNotIn("referral_removed", cats_src)
        self.assertEqual(anu_src["referral_removed"], "2026-11-15")  # 未恢复, 保留


class RejectionSeedTest(unittest.TestCase):
    def setUp(self):
        self._orig = pipeline.state.config.DATA_DIR
        self.tmp = tempfile.TemporaryDirectory()
        pipeline.state.config.DATA_DIR = self.tmp.name

    def tearDown(self):
        pipeline.state.config.DATA_DIR = self._orig
        self.tmp.cleanup()

    def test_drifted_rejection_reasserted(self):
        # 审计实拍: security.snssdk.com 拒收种子整个生命周期都躺在 active
        with open(os.path.join(self.tmp.name, "seed_rejections.json"), "w",
                  encoding="utf-8") as f:
            json.dump({"domains": [{"domain": "bad.example", "repo": AWAVENUE,
                                    "issue": 178, "reason": "保留拦截"}]}, f)
        st = state.empty_state()
        rec = state.merge_domain(st, "bad.example", {
            "repo": AWAVENUE, "kind": "rejected",
            "issues": [{"n": 178, "repo": AWAVENUE}]})
        rec["status"] = "active"  # drift
        fixed = pipeline._reapply_rejection_seeds(st)
        self.assertEqual(fixed, ["bad.example"])
        self.assertEqual(st["domains"]["bad.example"]["status"], "rejected")

    def test_no_seed_file_noop(self):
        self.assertEqual(
            pipeline._reapply_rejection_seeds(state.empty_state()), [])


if __name__ == "__main__":
    unittest.main()
