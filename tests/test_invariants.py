import unittest

from ad_whitelist_bot import invariants, state
from ad_whitelist_bot.config import ANTIAD, AWAVENUE


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
        conflicts = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
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
        conflicts = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual([d for d, _ in conflicts], ["child.parent.aw"])

    def test_conflict_applies_even_to_manual_approval(self):
        # charter: human approval cannot make a domain unblocked upstream
        st = build({"m.com": [{"repo": "manual", "kind": "manual", "issues": []}]})
        st["domains"]["m.com"]["approved_by"] = "manual_overrides"
        self.aa_block.add("m.com")
        conflicts = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual([d for d, _ in conflicts], ["m.com"])
        self.assertEqual(st["domains"]["m.com"]["status"], "conflict")

    def test_ancestor_antiad_block_is_info_only(self):
        # anti-AD @@ whitelist semantics: ancestor blocked, exact domain fine
        self.aa_block.add("mob.com")
        st = build({"code.sms.mob.com": [{"repo": ANTIAD, "kind": "whitelist-php",
                                          "value": 0,
                                          "issues": [{"n": 3, "repo": ANTIAD}]}]})
        conflicts = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
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
        conflicts = invariants.enforce_invariants(st, self.aw_main, self.aa_block)
        self.assertEqual(conflicts, [])
        self.assertEqual(st["domains"]["rej.com"]["status"], "rejected")


class RefreshCrossStatusTest(unittest.TestCase):
    def test_flags(self):
        st = build({"a.com": [{"repo": ANTIAD, "kind": "whitelist-php", "value": 0,
                               "issues": [{"n": 1, "repo": ANTIAD}]}]})
        invariants.refresh_cross_status(st, {"a.com"}, {"b.com"})
        self.assertTrue(st["domains"]["a.com"]["in_awavenue_main_now"])
        self.assertFalse(st["domains"]["a.com"]["in_antiad_block_now"])


if __name__ == "__main__":
    unittest.main()
