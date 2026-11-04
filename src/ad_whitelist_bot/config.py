"""Static configuration: repos, artifact URLs, maintainer sets, verdict phrases.

Everything a maintainer might need to tune lives here (or in data/*.json —
see README). No other module hardcodes repo slugs or phrase lists.
"""
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(REPO_ROOT, "data")
OUTPUT_DIR = os.path.join(REPO_ROOT, "output")
STATE_PATH = os.path.join(DATA_DIR, "state.json")

ANTIAD = "privacy-protection-tools/anti-AD"
AWAVENUE = "TG-Twilight/AWAvenue-Ads-Rule"
ALL_REPOS = (ANTIAD, AWAVENUE)

# Live artifacts fetched on every run
ANTIAD_WHITE_PHP_URL = (
    f"https://raw.githubusercontent.com/{ANTIAD}"
    "/adlist-maker/scripts/lib/white_domain_list.php"
)
ANTIAD_BLOCK_URL = f"https://raw.githubusercontent.com/{ANTIAD}/master/anti-ad-domains.txt"
AWAVENUE_RULE_URL = f"https://raw.githubusercontent.com/{AWAVENUE}/main/AWAvenue-Ads-Rule.txt"

# Maintainers: primary signal is GitHub author_association
# (OWNER / MEMBER / COLLABORATOR on the respective repo); these logins are a
# fallback belt-and-suspenders in case association is NONE for some reason.
MAINTAINERS: dict[str, set[str]] = {
    ANTIAD: {"MkQtS", "gentlyxu"},  # current + historical maintainer
    AWAVENUE: {"TG-Twilight"},
}
MAINT_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})

# ---------------------------------------------------------------- phrases --
# Issue is a false-positive candidate if title/body matches any of these.
CANDIDATE_RE = (
    r"误杀|误报|误拦截|误拦|错误拦截|被拦截|打不开|无法访问|无法打开|无法使用|"
    r"无法登录|无法加载|加载失败|加载异常|功能异常|功能失效|不能使用|异常|false[ -]?positive"
)

# Domain-submission / feature-request issues (adding BLOCK rules) are the
# opposite of false positives — never treat their maintainer replies as
# whitelist confirmations.
SUBMISSION_RE = (
    r"\[enhancement\]|提交拦截|提交广告|新增.{0,6}域名|收录.{0,4}域名|"
    r"添加.{0,4}域名|求添加|广告域名(提交|汇总)|拦截(这个|该|以下)域名"
)

# Maintainer comment phrases that confirm the fix (whitelist / removal).
# NOTE: deliberately NOT including ambiguous phrases like 已收录 — for
# submission issues that word means "added to the BLOCK list".
ACCEPT_RE = (
    r"已?加入白名单|加入白名单|已?加白|白名单(已|中)?(加|收录)|已修复|已经修复|已解决|已经解决|"
    r"已处理|已经处理|已移除|已经移除|将会移除|会移除|将会修复|会修复|会处理|"
    r"已更正|已修正|移至补充|迁移至补充|移动到补充|已清理|已经清理|"
    r"下个?版本|下一个版本|更新后生效|已修正该错误|\bfix(ed)?\b|done\b|will (fix|remove)"
)

# Maintainer comment phrases that reject the report.
REJECT_RE = (
    r"非误杀|不是误杀|非误拦截|正常拦截|正常范围|无法复现|不能复现|未能复现|"
    r"不予处理|不予修复|不会修复|不会移除|保留拦截|继续保留|维持拦截|维持现状|"
    r"不是我们|非本项目|不属于广告|不属于误|证据不足|无法核实|自行放行|自行添加|"
    r"建议自行|自行注释|自行手动|自己手动|手动放行|自行在相关|自行加白|自行加入"
)

# If an accepting comment also contains these, it is "self-service advice"
# (telling the reporter to whitelist it themselves) — NOT a project whitelist.
SELF_SERVICE_RE = r"自行|您自己|自己手动|手动放行|手动注释"
WHITELIST_VERB_RE = r"放行|加白|白名单|注释"
ALREADY_DONE_RE = r"已?(加入|移至|迁移)"
PENDING_MARK_RE = r"下个?版本|下一个版本|更新后生效|待发布|待更新"

GITHUB_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
PER_PAGE = 100
