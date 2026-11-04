import unittest

from ad_whitelist_bot import state
from ad_whitelist_bot.config import ANTIAD, AWAVENUE
from ad_whitelist_bot.sources import antiad, awavenue

PHP_SAMPLE = '''<?php
return [
    "cdn.xiaomi.com" => 0, //小米
    "withref.com" => 0, //误杀某站 #123
    "db5.example.akadns.net" => 0, // #268
    "extref.co.in" => 0, //https://github.com/nextdns/metadata/issues/364
    "removed.net" => -1, //失效
    // "commented.out" => 0, //整行注释
'''


class FakeClient:
    """Minimal client stub for scan tests: canned comments per issue number."""

    def __init__(self, comments_by_number):
        self._c = comments_by_number

    def comments(self, repo, number):
        return self._c.get(number, [])


def mk_issue(num, title, body="", state="closed", comments=0):
    return {"number": num, "title": title, "body": body, "state": state,
            "comments": comments, "updated_at": "2026-11-05T00:00:00Z"}


def c(user, body, assoc="NONE"):
    """Raw GitHub API comment shape (evaluate_issues does the normalization)."""
    return {"user": {"login": user}, "author_association": assoc, "body": body}


class ParseWhitePhpTest(unittest.TestCase):
    def test_parse_and_refs(self):
        entries = antiad.parse_white_php(PHP_SAMPLE)
        by = {e["domain"]: e for e in entries}
        self.assertEqual(by["removed.net"]["value"], -1)  # parse keeps; harvest filters
        self.assertNotIn("commented.out", by)  # commented-out line skipped
        self.assertEqual(by["withref.com"]["refs"], [(123, None)])
        self.assertEqual(by["db5.example.akadns.net"]["refs"], [(268, None)])
        self.assertEqual(by["extref.co.in"]["refs"], [(364, "nextdns/metadata")])
        self.assertEqual(by["cdn.xiaomi.com"]["refs"], [])

    def test_harvest_splits_by_provenance(self):
        records, noref = antiad.harvest_white_php(PHP_SAMPLE)
        self.assertIn("withref.com", records)
        self.assertIn("extref.co.in", records)
        self.assertNotIn("removed.net", records)
        self.assertNotIn("removed.net", noref)  # -1 excluded everywhere
        self.assertIn("cdn.xiaomi.com", noref)  # no refs -> reference file only


class AntiadCandidateTest(unittest.TestCase):
    def test_submission_gate(self):
        self.assertFalse(antiad.is_candidate(
            mk_issue(1, "[enhancement] <提交拦截域名> ad.foo.com")))
        self.assertTrue(antiad.is_candidate(
            mk_issue(2, "[误杀] foo.example.com 打不开")))
        self.assertFalse(antiad.is_candidate(mk_issue(3, "求添加广告拦截")))


class AntiadScanTest(unittest.TestCase):
    def test_confirmed_issue_only_goes_to_review_queue_shape(self):
        st = state.empty_state()
        issue = mk_issue(50, "[误杀] api.example.org", "打不开")
        client = FakeClient({50: [c("MkQtS", "已加入白名单", "COLLABORATOR")]})
        issue_only = antiad.scan_issues(client, [issue], st)
        self.assertIn("api.example.org", issue_only)
        rec = st["issues"][ANTIAD]["50"]
        self.assertEqual(rec["status"], "done")
        self.assertEqual(rec["verdict"], "confirmed")
        self.assertEqual(rec["domains"], ["api.example.org"])

    def test_rejected_recorded(self):
        st = state.empty_state()
        issue = mk_issue(51, "[误杀] ads.foo.com")
        client = FakeClient({51: [c("MkQtS", "这是正常广告，维持拦截", "COLLABORATOR")]})
        antiad.scan_issues(client, [issue], st)
        self.assertEqual(st["issues"][ANTIAD]["51"]["status"], "rejected")
        self.assertNotIn("ads.foo.com", st["domains"])

    def test_locked_issue_never_reevaluated(self):
        st = state.empty_state()
        st["issues"][ANTIAD]["52"] = {"status": "done", "locked": True}
        issue = mk_issue(52, "[误杀] whatever.com")
        client = FakeClient({52: [c("MkQtS", "已加入白名单", "COLLABORATOR")]})
        antiad.scan_issues(client, [issue], st, full=True)
        self.assertEqual(st["issues"][ANTIAD]["52"].get("domains"), None,
                         "locked record must stay untouched")

    def test_mass_report_body_domains_not_harvested(self):
        # domains listed only in the BODY of a mass report must not attach
        st = state.empty_state()
        body = "相关域名:\na.com\nb.com\nc.com\n(许多无关域)"
        issue = mk_issue(53, "[误杀] only-this.com 打不开", body)
        client = FakeClient({53: [c("MkQtS", "已加入白名单", "COLLABORATOR")]})
        issue_only = antiad.scan_issues(client, [issue], st)
        self.assertEqual(set(issue_only), {"only-this.com"})


class AwavenueCandidateTest(unittest.TestCase):
    def test_gate(self):
        self.assertFalse(awavenue.is_candidate(
            mk_issue(1, "[enhancement] <提交拦截域名>")))
        self.assertTrue(awavenue.is_candidate(
            mk_issue(2, "[BUG] 某App无法加载")))


class AwavenueScanTest(unittest.TestCase):
    def test_confirmed_closed_auto_active(self):
        st = state.empty_state()
        body = "相关域名：\nfp.example.com\n"
        issue = mk_issue(10, "[BUG] 某功能失效", body)
        client = FakeClient({10: [c("TG-Twilight", "好的，我们会移除它", "OWNER")]})
        confirmed = awavenue.scan_issues(client, [issue], st, {"other.aw"})
        self.assertIn("fp.example.com", confirmed)
        self.assertEqual(st["issues"][AWAVENUE]["10"]["status"], "done")

    def test_confirmed_but_still_in_rule_is_filtered(self):
        st = state.empty_state()
        issue = mk_issue(11, "[BUG] 某功能失效", "相关域名：\nstillblocked.example.com\n")
        client = FakeClient({11: [c("TG-Twilight", "已经移除了", "OWNER")]})
        confirmed = awavenue.scan_issues(client, [issue], st,
                                         {"stillblocked.example.com"})
        self.assertNotIn("stillblocked.example.com", confirmed)

    def test_confirmed_open_issue_goes_pending(self):
        # audit fix: maintainer announced the fix but issue still open
        st = state.empty_state()
        issue = mk_issue(12, "[BUG] 某功能失效", "相关域名：\nsoon.example.com\n",
                         state="open")
        client = FakeClient({12: [c("TG-Twilight", "好的，我们会移除它", "OWNER")]})
        confirmed = awavenue.scan_issues(client, [issue], st, set())
        self.assertEqual(confirmed, {})
        rec = st["issues"][AWAVENUE]["12"]
        self.assertEqual(rec["status"], "pending")
        self.assertEqual(rec["domains"], ["soon.example.com"])

    def test_promote_pending(self):
        st = state.empty_state()
        st["issues"][AWAVENUE]["12"] = {
            "status": "pending", "verdict": "confirmed",
            "domains": ["soon.example.com"]}
        promoted = awavenue.promote_pending(st, set())  # rule without the domain
        self.assertEqual(promoted, ["soon.example.com"])
        self.assertEqual(st["issues"][AWAVENUE]["12"]["status"], "done")
        self.assertIn("soon.example.com", st["domains"])
        self.assertEqual(st["domains"]["soon.example.com"]["status"], "active")

    def test_promote_pending_waits_while_still_blocked(self):
        st = state.empty_state()
        st["issues"][AWAVENUE]["12"] = {
            "status": "pending", "verdict": "confirmed",
            "domains": ["soon.example.com"]}
        promoted = awavenue.promote_pending(st, {"soon.example.com"})
        self.assertEqual(promoted, [])
        self.assertEqual(st["issues"][AWAVENUE]["12"]["status"], "pending")


if __name__ == "__main__":
    unittest.main()
