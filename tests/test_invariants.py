import unittest

from ad_whitelist_bot import invariants, state
from ad_whitelist_bot.config import ADG_DNS, ANTIAD, AWAVENUE


def build(domains_spec):
    st = state.empty_state()
    for d, sources in domains_spec.items():
        rec = state.merge_domain(st, d, sources[0])
        for s in sources[1:]:
            state.merge_domain(st, d, s)
    return st


class EnforceInvariantsTest(unittest.TestCase):
    def setUp(self):
        self.aa_block = {"blocked.example"}
        self.aw_main = {"ad.aw"}

    def test_exact_antiad_block_conflict(self):
        st = build({"bad.com": [{"repo": ANTIAD, "kind": "whitelist-php",
                                 "value": 0, "issues": [{"n": 1, "repo": ANTIAD}]}],
                    "good.com": [{"repo": ANTIAD, "kind": "whitelist-php",
                                  "value": 0, "issues": [{"n": 2, "repo": ANTIAD}]}]})
        # make bad.com exactly present in the blocklist
        self.aa_block.add("bad.com")
        conflicts, _ = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual([d for d, _ in conflicts], ["bad.com"])
        self.assertEqual(st["domains"]["bad.com"]["status"], "conflict")
        self.assertEqual(st["domains"]["good.com"]["status"], "active")

    def test_awavenue_ancestor_conflict(self):
        self.aw_main.add("parent.aw")
        st = build({
            "child.parent.aw": [{"repo": AWAVENUE, "kind": "issue-confirmed",
                                 "issues": [{"n": 9, "repo": AWAVENUE}]}],
            "other.aw": [{"repo": AWAVENUE, "kind": "issue-confirmed",
                          "issues": [{"n": 9, "repo": AWAVENUE}]}],
        })
        conflicts, _ = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual([d for d, _ in conflicts], ["child.parent.aw"])

    def test_conflict_applies_even_to_manual_approval(self):
        # charter: human approval cannot make a domain unblocked upstream
        st = build({"m.com": [{"repo": "manual", "kind": "manual", "issues": []}]})
        st["domains"]["m.com"]["approved_by"] = "manual_overrides"
        self.aa_block.add("m.com")
        conflicts, _ = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual([d for d, _ in conflicts], ["m.com"])
        self.assertEqual(st["domains"]["m.com"]["status"], "conflict")

    def test_ancestor_antiad_block_is_info_only(self):
        # anti-AD @@ whitelist semantics: ancestor blocked, exact domain fine
        self.aa_block.add("mob.com")
        st = build({"code.sms.mob.com": [{"repo": ANTIAD, "kind": "whitelist-php",
                                          "value": 0,
                                          "issues": [{"n": 3, "repo": ANTIAD}]}]})
        conflicts, _ = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual(conflicts, [])
        self.assertEqual(st["domains"]["code.sms.mob.com"]["status"], "active")
        self.assertIn("partial_block", st["domains"]["code.sms.mob.com"])

    def test_partial_block_flag_cleared_when_no_longer_ancestor_blocked(self):
        self.aa_block.add("mob.com")
        st = build({"code.sms.mob.com": [{"repo": ANTIAD, "kind": "whitelist-php",
                                          "value": 0,
                                          "issues": [{"n": 3, "repo": ANTIAD}]}]})
        invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.aa_block.discard("mob.com")
        invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertNotIn("partial_block", st["domains"]["code.sms.mob.com"])

    def test_non_active_domains_untouched(self):
        st = build({"rej.com": [{"repo": AWAVENUE, "kind": "rejected", "issues": []}]})
        st["domains"]["rej.com"]["status"] = "rejected"
        self.aw_main.add("rej.com")
        conflicts, _ = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual(conflicts, [])
        self.assertEqual(st["domains"]["rej.com"]["status"], "rejected")


class RefreshCrossStatusTest(unittest.TestCase):
    def test_flags(self):
        st = build({"a.com": [{"repo": ANTIAD, "kind": "whitelist-php", "value": 0,
                               "issues": [{"n": 1, "repo": ANTIAD}]}]})
        invariants.refresh_cross_status(st, {"a.com"}, {"b.com"})
        self.assertTrue(st["domains"]["a.com"]["in_awavenue_main_now"])
        self.assertFalse(st["domains"]["a.com"]["in_antiad_block_now"])


class ConflictRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.aa_block = {"blocked.example"}
        self.aw_main = {"ad.aw"}

    def test_recovery_to_active_with_php_backing(self):
        self.aa_block.add("bad.com")
        st = build({"bad.com": [{"repo": ANTIAD, "kind": "whitelist-php",
                                 "value": 0, "issues": [{"n": 1, "repo": ANTIAD}]}]})
        invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual(st["domains"]["bad.com"]["status"], "conflict")
        self.aa_block.discard("bad.com")  # 上游解除拦截
        conflicts, recovered = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual(conflicts, [])
        self.assertEqual(recovered, [("bad.com", "active")])
        self.assertEqual(st["domains"]["bad.com"]["status"], "active")
        self.assertNotIn("conflict", st["domains"]["bad.com"])

    def test_recovery_to_pending_without_backing(self):
        self.aa_block.add("bad.com")
        st = build({"bad.com": [{"repo": ANTIAD, "kind": "whitelist-php",
                                 "value": 0, "issues": [{"n": 1, "repo": ANTIAD}]}]})
        invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        for s in st["domains"]["bad.com"]["sources"]:
            s["php_removed"] = "2026-11-15"  # 背书已撤
        self.aa_block.discard("bad.com")
        conflicts, recovered = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual(recovered, [("bad.com", "pending")])
        self.assertEqual(st["domains"]["bad.com"]["status"], "pending")

    def test_recovery_with_manual_approval_goes_active(self):
        self.aa_block.add("m.com")
        st = build({"m.com": [{"repo": "manual", "kind": "manual", "issues": []}]})
        invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        st["domains"]["m.com"]["approved_by"] = "manual_overrides"
        self.aa_block.discard("m.com")
        conflicts, recovered = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual(recovered, [("m.com", "active")])

    def test_approved_domain_stays_conflicted_while_blocked(self):
        # 章程:批准不能豁免;已 conflict 域重复跑不得重复上报
        self.aa_block.add("m.com")
        st = build({"m.com": [{"repo": "manual", "kind": "manual", "issues": []}]})
        st["domains"]["m.com"]["approved_by"] = "manual_overrides"
        conflicts, _ = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual([d for d, _ in conflicts], ["m.com"])
        conflicts2, recovered2 = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual(conflicts2, [], "already-conflicted must not re-report")
        self.assertEqual(recovered2, [])
        self.assertEqual(st["domains"]["m.com"]["status"], "conflict")


class PerSourceInvariantTest(unittest.TestCase):
    """逐源源内零交集(11-15 门槛实测:全局互检会灭新源 295/630 并错杀现役 21 条)"""

    def setUp(self):
        self.aa_block = {"blocked.example"}
        self.aw_main = {"ad.aw"}
        self.adg_block = {"fp.adguard.test"}

    def test_adguard_exact_hit_conflicts_for_adguard_source(self):
        st = build({"fp.adguard.test": [{"repo": ADG_DNS, "kind": "dns-exclusion",
                                         "issues": [{"n": 1, "repo": ADG_DNS}]}]})
        conflicts, _ = invariants.enforce_invariants(
            st, self.aw_main, self.aa_block, self.adg_block)
        self.assertEqual([d for d, _ in conflicts], ["fp.adguard.test"])

    def test_cross_source_disagreement_is_not_a_conflict(self):
        # anti-AD 背书的域名被 AdGuard DNS filter 精确拦(236 条实测场景)
        # → 逐源语义下不剔除,refresh_cross_status 注记
        st = build({"cn-func.com": [{"repo": ANTIAD, "kind": "whitelist-php",
                                     "value": 0, "issues": [{"n": 1, "repo": ANTIAD}]}]})
        adg_block = self.adg_block | {"cn-func.com"}
        conflicts, recovered = invariants.enforce_invariants(
            st, self.aw_main, self.aa_block, adg_block)
        invariants.refresh_cross_status(st, self.aw_main, self.aa_block, adg_block)
        self.assertEqual(conflicts, [])
        self.assertEqual(recovered, [])
        self.assertEqual(st["domains"]["cn-func.com"]["status"], "active")
        self.assertTrue(st["domains"]["cn-func.com"]["in_adguard_filter_now"])

    def test_manual_checked_against_all_products(self):
        st = build({"m.com": [{"repo": "manual", "kind": "manual", "issues": []}]})
        self.adg_block.add("m.com")
        conflicts, _ = invariants.enforce_invariants(
            st, self.aw_main, self.aa_block, self.adg_block)
        self.assertEqual([d for d, _ in conflicts], ["m.com"])

    def test_adguard_ancestor_is_informational(self):
        self.adg_block.add("parent.adg")
        st = build({"sub.parent.adg": [{"repo": ADG_DNS, "kind": "dns-exception",
                                        "issues": [{"n": 2, "repo": ADG_DNS}]}]})
        conflicts, _ = invariants.enforce_invariants(
            st, self.aw_main, self.aa_block, self.adg_block)
        self.assertEqual(conflicts, [])
        self.assertEqual(st["domains"]["sub.parent.adg"]["status"], "active")
        self.assertIn("adguard_ancestor_block", st["domains"]["sub.parent.adg"])


if __name__ == "__main__":
    unittest.main()
