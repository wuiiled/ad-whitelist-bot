import unittest

from ad_whitelist_bot import extract


class CleanDomainTest(unittest.TestCase):
    def test_plain_domain(self):
        self.assertEqual(extract.clean_domain("Example.COM."), "example.com")

    def test_rejects_file_extensions(self):
        for t in ("shot.png", "list.md", "rules.conf", "bundle.jar",
                  "img.webp", "app.srs", "list.txt", "main.py"):
            self.assertIsNone(extract.clean_domain(t), t)

    def test_rejects_fake_tlds(self):
        # artifacts seen in issue text
        for t in ("1.microsoft", "2.clash", "thread.message", "xx.yy",
                  "com.azure.authenticator"):
            self.assertIsNone(extract.clean_domain(t), t)

    def test_real_tlds_pass(self):
        for t in ("pan.baidu.com", "cip.cc", "suo.im", "naifei.shop",
                  "xj-n-tax.gov.cn", "tongji.edu.cn", "tracker.hdsky.me"):
            self.assertEqual(extract.clean_domain(t), t, t)

    def test_rejects_ips_and_short_tokens(self):
        self.assertIsNone(extract.clean_domain("1.2.3.4"))
        self.assertIsNone(extract.clean_domain("example"))
        self.assertIsNone(extract.clean_domain(""))

    def test_rejects_exact_junk_and_screenshots(self):
        self.assertIsNone(extract.clean_domain("github.com"))
        self.assertIsNone(extract.clean_domain("screenshot_2024.img.example.com"))

    def test_second_level_tld_allow(self):
        self.assertEqual(extract.clean_domain("x.example.com.cn"), "x.example.com.cn")


class ExtractDomainsTest(unittest.TestCase):
    def test_ordered_unique(self):
        text = "访问 pan.baidu.com 失败,另见 pan.baidu.com 和 cip.cc。"
        self.assertEqual(extract.extract_domains(text), ["pan.baidu.com", "cip.cc"])

    def test_none_and_empty(self):
        self.assertEqual(extract.extract_domains(None), [])
        self.assertEqual(extract.extract_domains(""), [])


class SuffixBlockedTest(unittest.TestCase):
    def test_exact_and_ancestor(self):
        block = {"example.com", "a.b.c"}
        self.assertTrue(extract.suffix_blocked("example.com", block))
        self.assertTrue(extract.suffix_blocked("sub.example.com", block))
        self.assertTrue(extract.suffix_blocked("x.a.b.c", block))
        self.assertFalse(extract.suffix_blocked("notexample.com", block))
        self.assertFalse(extract.suffix_blocked("example.org", block))


class RuleLineTest(unittest.TestCase):
    def test_parse_rule_domain_line(self):
        self.assertEqual(extract.parse_rule_domain_line("||foo.bar^"), "foo.bar")
        self.assertEqual(extract.parse_rule_domain_line("||foo.bar^$important"), "foo.bar")
        self.assertIsNone(extract.parse_rule_domain_line("! comment"))
        self.assertIsNone(extract.parse_rule_domain_line("plain.line"))

    def test_blocklist_parsers(self):
        self.assertEqual(extract.parse_domain_blocklist("# c\na.com\n\nB.COM\n"),
                         {"a.com", "b.com"})
        self.assertEqual(extract.parse_adguard_rule_domainset("||a.com^\n||b.org^$x\n"),
                         {"a.com", "b.org"})


if __name__ == "__main__":
    unittest.main()
