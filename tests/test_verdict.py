import unittest

from ad_whitelist_bot import verdict
from ad_whitelist_bot.config import ANTIAD, AWAVENUE


def c(user, body, assoc="NONE"):
    return {"user": user, "author_association": assoc, "body": body}


class IsMaintainerTest(unittest.TestCase):
    def test_association(self):
        self.assertTrue(verdict.is_maintainer("x", "OWNER", AWAVENUE))
        self.assertTrue(verdict.is_maintainer("x", "COLLABORATOR", ANTIAD))
        self.assertFalse(verdict.is_maintainer("x", "NONE", ANTIAD))

    def test_fallback_login_list(self):
        self.assertTrue(verdict.is_maintainer("MkQtS", "NONE", ANTIAD))
        self.assertTrue(verdict.is_maintainer("TG-Twilight", "NONE", AWAVENUE))
        self.assertFalse(verdict.is_maintainer("random", "NONE", ANTIAD))


class ClassifyCommentTest(unittest.TestCase):
    def test_accept(self):
        self.assertEqual(verdict.classify_comment("已经移除，感谢反馈"), "accept")
        self.assertEqual(verdict.classify_comment("已加入白名单，下个版本生效"), "accept")
        self.assertEqual(verdict.classify_comment("ok, we'll fix it."), "accept")

    def test_reject(self):
        self.assertEqual(verdict.classify_comment("无法复现，请提供证据"), "reject")
        self.assertEqual(verdict.classify_comment("这个域名会继续保留拦截"), "reject")

    def test_self_service(self):
        self.assertEqual(
            verdict.classify_comment("如果您实在有需要，建议您自行在相关界面放行该域名"),
            "self_service")

    def test_last_sentence_wins(self):
        # accept earlier, reject later -> reject
        body = "好的我们会移除它。不过经过讨论，这条域名应该保留拦截。"
        self.assertEqual(verdict.classify_comment(body), "reject")
        # reject earlier, accept later -> accept
        body2 = "一开始不想处理。但经复核确认是误杀，已经移除了。"
        self.assertEqual(verdict.classify_comment(body2), "accept")

    def test_no_signal(self):
        self.assertIsNone(verdict.classify_comment("感谢反馈"))
        self.assertIsNone(verdict.classify_comment(""))


class VerdictFromCommentsTest(unittest.TestCase):
    def test_maintainer_confirmed_and_body_returned(self):
        cs = [c("reporter", "xxx 打不开了"),
              c("TG-Twilight", "好的，我们会移除它", "OWNER")]
        v, ev, body = verdict.verdict_from_comments(cs, AWAVENUE)
        self.assertEqual(v, "confirmed")
        self.assertIn("移除", ev)
        self.assertIn("移除", body)

    def test_non_maintainer_ignored(self):
        cs = [c("randomguy", "已经移除了啦")]
        v, _, _ = verdict.verdict_from_comments(cs, AWAVENUE)
        self.assertIsNone(v)

    def test_reject_overrides_earlier_accept(self):
        cs = [c("MkQtS", "已加入白名单", "COLLABORATOR"),
              c("MkQtS", "核实后这是正常广告，维持拦截", "COLLABORATOR")]
        v, _, _ = verdict.verdict_from_comments(cs, ANTIAD)
        self.assertEqual(v, "rejected")

    def test_pending_mark(self):
        cs = [c("MkQtS", "已加入白名单，下个版本更新生效", "COLLABORATOR")]
        v, _, _ = verdict.verdict_from_comments(cs, ANTIAD)
        self.assertEqual(v, "confirmed_pending")

    def test_self_service_only_if_no_stronger(self):
        cs = [c("TG-Twilight", "建议自行放行", "OWNER"),
              c("TG-Twilight", "已经修复了", "OWNER")]
        v, _, _ = verdict.verdict_from_comments(cs, AWAVENUE)
        self.assertEqual(v, "confirmed")


if __name__ == "__main__":
    unittest.main()
