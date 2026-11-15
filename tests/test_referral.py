"""Referral source: parsing, merge semantics, tier split, invariant keys."""
import unittest

from ad_whitelist_bot import invariants, render, state
from ad_whitelist_bot.config import ADG_DNS, ANUDEEP, CATS
from ad_whitelist_bot.sources import referral

CATS_FIXTURE = """\
#!-白名单-!#

#! Apple 白名单 Start !#
#iCloud
cu-cn-north00002.gala.convection.cn
cu-cn-north00001.gala.convection.cn

#苹果商店
xp.apple.com
#! Apple 白名单 End !#

#! 百度 白名单 Start !#
#百度地图 #201
newvector.map.baidu.com
#贴吧网页版表情 #146
gsp0.baidu.com
#! 百度 白名单 End !#

#正则行应被拒
is[0-9]\\-ssl.mzstatic.com
#单标签应被拒
localhost
#IP应被拒
192.168.1.1
0.client-channel.google.com
"""

ANUDEEP_FIXTURE = """\
0.client-channel.google.com
1drv.com
akamaihd.net
amazonaws.com
"""

EXC_FIXTURE = """\
# AdGuard exceptions
! https://github.com/AdguardTeam/AdGuardSDNSFilter/issues/12
@@||annotated.example.com^|

@@||unannotated.example.org^|
! explanatory note keeps the block
@@||unannotated2.example.net^|
"""


class ParseDomainLineTest(unittest.TestCase):
    def test_accepts_consumer_semantics(self):
        self.assertEqual(referral.parse_domain_line("XP.Apple.com"), "xp.apple.com")
        self.assertEqual(referral.parse_domain_line("0.client-channel.google.com"),
                         "0.client-channel.google.com")
        self.assertEqual(referral.parse_domain_line("a.b-c_d.example.co.uk"),
                         "a.b-c_d.example.co.uk")

    def test_rejects_junk(self):
        for line in ["", "# comment", "#! section !#", "is[0-9]\\-ssl.mzstatic.com",
                     "localhost", "192.168.1.1", "a.example.com/path",
                     "*.example.com", "a.example.com:443", "1.2.3.4",
                     "a..b.com", "-lead.example.com", "example-.com"]:
            self.assertIsNone(referral.parse_domain_line(line), line)


class HarvestTest(unittest.TestCase):
    def test_cats_binding(self):
        recs = referral.harvest_cats(CATS_FIXTURE)
        self.assertEqual(set(recs), {
            "cu-cn-north00002.gala.convection.cn",
            "cu-cn-north00001.gala.convection.cn",
            "xp.apple.com", "newvector.map.baidu.com", "gsp0.baidu.com",
            "0.client-channel.google.com"})
        # section marker + plain comment cleared the earlier ref block
        self.assertNotIn("issues", recs["xp.apple.com"]["sources"][0])
        # `#N` comment refs bind to the following domain run
        src = recs["newvector.map.baidu.com"]["sources"][0]
        self.assertEqual(src["issues"], [{"n": 201, "repo": CATS}])
        src = recs["gsp0.baidu.com"]["sources"][0]
        self.assertEqual(src["issues"], [{"n": 146, "repo": CATS}])
        # section marker between ref blocks prevents leakage
        self.assertNotIn("issues", recs["0.client-channel.google.com"]["sources"][0])

    def test_anudeep(self):
        recs = referral.harvest_anudeep(ANUDEEP_FIXTURE)
        self.assertEqual(set(recs), {"0.client-channel.google.com", "1drv.com",
                                     "akamaihd.net", "amazonaws.com"})
        self.assertEqual(recs["akamaihd.net"]["sources"][0]["repo"], ANUDEEP)

    def test_exceptions_noref_split(self):
        traced = {"annotated.example.com"}
        recs = referral.harvest_exceptions_noref(EXC_FIXTURE, traced)
        self.assertEqual(set(recs), {"unannotated.example.org",
                                     "unannotated2.example.net"})
        self.assertEqual(recs["unannotated.example.org"]["sources"][0]["repo"],
                         ADG_DNS)

    def test_build_records_merges_sources(self):
        recs = referral.build_records(CATS_FIXTURE, ANUDEEP_FIXTURE,
                                      EXC_FIXTURE, {"annotated.example.com"})
        # 0.client-channel.google.com appears in BOTH cats and anudeep
        srcs = recs["0.client-channel.google.com"]["sources"]
        self.assertEqual({s["repo"] for s in srcs}, {CATS, ANUDEEP})

    def test_comment_after_domain_resets_refs(self):
        # 真实文件实测(2026-11-16): 消费过域名后再遇注释行必须清掉上一轮 refs,
        # 否则 `#百度地图 #201` 会污染 `#额外` 块的 sv.map.baidu.com
        text = ("#百度地图 #201\n"
                "newvector.map.baidu.com\n"
                "#额外\n"
                "sv.map.baidu.com\n")
        recs = referral.harvest_cats(text)
        self.assertEqual(recs["newvector.map.baidu.com"]["sources"][0]["issues"],
                         [{"n": 201, "repo": CATS}])
        self.assertNotIn("issues", recs["sv.map.baidu.com"]["sources"][0])


class MergeReferralTest(unittest.TestCase):
    def _rec(self, domain):
        return {domain: {"domain": domain, "sources": [
            {"repo": CATS, "kind": "referral", "action": "curated"}]}}

    def test_new_record_active(self):
        st = state.empty_state()
        added, supp = state.merge_referral(st, self._rec("a.com"))
        self.assertEqual((added, supp), (["a.com"], []))
        self.assertEqual(st["domains"]["a.com"]["status"], "active")

    def test_never_promotes_pending(self):
        st = state.empty_state()
        state.merge_domain(st, "p.com", {
            "repo": "antiad", "kind": "issue-only", "issues": []})
        st["domains"]["p.com"]["status"] = "pending"
        added, supp = state.merge_referral(st, self._rec("p.com"))
        self.assertEqual((added, supp), ([], ["p.com"]))
        self.assertEqual(st["domains"]["p.com"]["status"], "pending")
        # no referral source leaked into the pending record
        self.assertEqual({s["kind"] for s in st["domains"]["p.com"]["sources"]},
                         {"issue-only"})

    def test_never_resurrects_rejected(self):
        st = state.empty_state()
        rec = state.merge_domain(st, "r.com", {
            "repo": "antiad", "kind": "rejected", "action": "rejected"})
        rec["status"] = "rejected"
        added, supp = state.merge_referral(st, self._rec("r.com"))
        self.assertEqual((added, supp), ([], ["r.com"]))
        self.assertEqual(st["domains"]["r.com"]["status"], "rejected")

    def test_conflict_keeps_status_gains_provenance(self):
        st = state.empty_state()
        rec = state.merge_domain(st, "c.com", {
            "repo": "antiad", "kind": "whitelist-php", "value": 0})
        rec["status"] = "conflict"
        added, supp = state.merge_referral(st, self._rec("c.com"))
        self.assertEqual((added, supp), ([], []))
        self.assertEqual(st["domains"]["c.com"]["status"], "conflict")
        self.assertEqual({s["kind"] for s in st["domains"]["c.com"]["sources"]},
                         {"whitelist-php", "referral"})

    def _self_demoted_pending(self, st, domain):
        rec = state.merge_domain(st, domain, {
            "repo": CATS, "kind": "referral", "action": "curated"})
        rec["status"] = "pending"
        rec["demoted_by"] = "referral-removal"
        return rec

    def test_self_demoted_pending_restored_on_readd(self):
        # 上游把删掉的域名加回来: 机器自降级的 pending 随正常合并复活
        # (flag 已由 pipeline 对账层按 repo 清除, merge 只负责放行与翻转)
        st = state.empty_state()
        self._self_demoted_pending(st, "r.com")
        added, supp = state.merge_referral(st, self._rec("r.com"))
        self.assertEqual((added, supp), ([], []))
        rec = st["domains"]["r.com"]
        self.assertEqual(rec["status"], "active")
        self.assertEqual(len(rec["sources"]), 1)  # 对账后 source 相等, 不重复追加
        self.assertNotIn("demoted_by", rec)

    def test_issue_queued_pending_never_restored_by_referral(self):
        # 交错场景: referral 活跃域收到 issue 确认转人工 → 上游删/加回,
        # referral 证据不得把人工队列里的记录晋升出去(章程护栏)
        st = state.empty_state()
        rec = state.merge_domain(st, "q.com", {
            "repo": "antiad", "kind": "issue-only", "issues": []})
        rec["status"] = "pending"
        rec["demoted_by"] = "referral-removal"
        rec["sources"].append({"repo": CATS, "kind": "referral",
                               "action": "curated",
                               "referral_removed": "2026-11-15"})
        added, supp = state.merge_referral(st, self._rec("q.com"))
        self.assertEqual((added, supp), ([], ["q.com"]))
        self.assertEqual(st["domains"]["q.com"]["status"], "pending")
        # flag 未被清除(仍处于人工队列, 复活须走人工或新 traced 证据)
        self.assertTrue(st["domains"]["q.com"]["sources"][1].get("referral_removed"))

    def test_rejected_never_restored(self):
        st = state.empty_state()
        rec = self._self_demoted_pending(st, "r.com")
        rec["status"] = "rejected"
        added, supp = state.merge_referral(st, self._rec("r.com"))
        self.assertEqual((added, supp), ([], ["r.com"]))
        self.assertEqual(st["domains"]["r.com"]["status"], "rejected")  # 拒绝粘滞


class InvariantKeysTest(unittest.TestCase):
    def test_referral_only_no_keys(self):
        rec = {"sources": [{"repo": CATS, "kind": "referral"}]}
        self.assertEqual(invariants._checked_keys(rec), ())

    def test_referral_never_tightens_traced_keys(self):
        rec = {"sources": [{"repo": "privacy-protection-tools/anti-AD",
                            "kind": "whitelist-php", "value": 0},
                           {"repo": CATS, "kind": "referral"}]}
        self.assertEqual(invariants._checked_keys(rec), ("antiad",))

    def test_traced_behavior_unchanged(self):
        rec = {"sources": [{"repo": "manual", "kind": "manual"}]}
        self.assertEqual(invariants._checked_keys(rec),
                         ("antiad", "awavenue", "adguard"))
        # unknown repo slugs carry no mapped product -> no keys (as before)
        rec = {"sources": [{"repo": "x/y", "kind": "dns-exclusion"}]}
        self.assertEqual(invariants._checked_keys(rec), ())
        rec = {"sources": [{"repo": "privacy-protection-tools/anti-AD",
                            "kind": "whitelist-php", "value": 0}]}
        self.assertEqual(invariants._checked_keys(rec), ("antiad",))

    def test_referral_counts_as_backing(self):
        rec = {"sources": [{"repo": CATS, "kind": "referral"}]}
        self.assertTrue(invariants.has_active_backing(rec))
        # 已退役(上游删除)的 referral 源不再构成背书 — 同 php_removed 语义
        retired = {"sources": [{"repo": CATS, "kind": "referral",
                                "referral_removed": "2026-11-16"}]}
        self.assertFalse(invariants.has_active_backing(retired))


class TierSplitTest(unittest.TestCase):
    def _st(self):
        st = state.empty_state()
        state.merge_domain(st, "bare-traced.com", {
            "repo": "antiad", "kind": "whitelist-php", "value": 0})
        state.merge_domain(st, "bare-referral.net", {
            "repo": CATS, "kind": "referral"})
        state.merge_domain(st, "deep.traced.org", {
            "repo": "antiad", "kind": "whitelist-php", "value": 0})
        state.merge_domain(st, "deep.referral.org", {
            "repo": ANUDEEP, "kind": "referral"})
        return st

    def test_split(self):
        st = self._st()
        with __import__("tempfile").TemporaryDirectory() as tmp:
            doms = render.render_lists(st, tmp)
            main = open(f"{tmp}/merged_false_positive_whitelist.txt",
                        encoding="utf-8").read().splitlines()
            exact = open(f"{tmp}/merged_false_positive_whitelist_exact.txt",
                         encoding="utf-8").read().splitlines()
        self.assertEqual(len(doms), 4)
        main_doms = {l for l in main if l and not l.startswith("#")}
        exact_doms = {l for l in exact if l and not l.startswith("#")}
        self.assertEqual(exact_doms, {"bare-traced.com"})
        self.assertEqual(main_doms, {"bare-referral.net", "deep.traced.org",
                                     "deep.referral.org"})


if __name__ == "__main__":
    unittest.main()
