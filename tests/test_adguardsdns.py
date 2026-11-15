import unittest

from ad_whitelist_bot.config import ADG_DNS
from ad_whitelist_bot.sources import adguardsdns

EXCL_SAMPLE = """
! https://github.com/AdguardTeam/AdGuardSDNSFilter/issues/2084
! Blocked by CNAME data.adobec.net
||data.email.tangerine.ca^
||aurorabrand.co.il^
! https://github.com/AdguardTeam/AdguardFilters/issues/233722
||target-video.com^

||unannotated.example^
||blocked.example^$important
"""

EXC_SAMPLE = """
! https://github.com/AdguardTeam/AdGuardSDNSFilter/issues/2134
! Blocked by CNAME omtrdc.net
@@||analytics.cibc.com^|
@@||unsubscribe.email.premierleague.com^$important
@@||scoped.example^$domain=foo.com
"""


class HarvestExclusionsTest(unittest.TestCase):
    def test_annotation_block_binds_to_consecutive_rules(self):
        records, noref = adguardsdns.harvest_exclusions(EXCL_SAMPLE)
        # 一条注释块覆盖紧随的两条规则
        for d in ("data.email.tangerine.ca", "aurorabrand.co.il"):
            src = records[d]["sources"][0]
            self.assertEqual(src["kind"], "dns-exclusion")
            self.assertEqual(src["issues"], [{"n": 2084, "repo": ADG_DNS}])
            self.assertIn("Blocked by CNAME", src["action"])
        # 新注释块切换归属(跨仓库 issue 也归因)
        self.assertEqual(records["target-video.com"]["sources"][0]["issues"],
                         [{"n": 233722, "repo": "AdguardTeam/AdguardFilters"}])
        # 空行清空 → 无注释条目入 noref 参考层
        self.assertNotIn("unannotated.example", records)
        self.assertIn("unannotated.example", noref)
        # $ 修饰符规则被拒(缺陷3 语义),不进 records 也不进 noref
        self.assertNotIn("blocked.example", records)
        self.assertNotIn("blocked.example", noref)


class HarvestExceptionsTest(unittest.TestCase):
    def test_allow_forms(self):
        records, _ = adguardsdns.harvest_exceptions(EXC_SAMPLE)
        self.assertIn("analytics.cibc.com", records)
        self.assertEqual(records["analytics.cibc.com"]["sources"][0]["kind"],
                         "dns-exception")
        # $important 容忍
        self.assertIn("unsubscribe.email.premierleague.com", records)
        # $domain= 限定拒收
        self.assertNotIn("scoped.example", records)


class HarvestMergeTest(unittest.TestCase):
    def test_both_files_merge(self):
        # a.example 带注释进 records;b.example 走 exceptions 解析
        records, _ = adguardsdns.harvest(
            "! https://github.com/AdguardTeam/AdGuardSDNSFilter/issues/1\n||a.example^\n",
            "! https://github.com/AdguardTeam/AdGuardSDNSFilter/issues/2\n@@||b.example^|\n")
        self.assertIn("a.example", records)
        self.assertIn("b.example", records)
        self.assertEqual(records["a.example"]["sources"][0]["repo"], ADG_DNS)
        self.assertEqual(records["b.example"]["sources"][0]["kind"], "dns-exception")


if __name__ == "__main__":
    unittest.main()
