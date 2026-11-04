"""Render output artifacts: domain lists, provenance, run report, references."""
from __future__ import annotations

import logging
import os
import re
from datetime import date

from . import config
from .state import State

log = logging.getLogger(__name__)

HEADER_NOTE = [
    "误报白名单 — 域名在 anti-AD / AWAvenue-Ads-Rule 的 GitHub issue 中被报告为误报,",
    "并经维护者复核后加入排除名单(anti-AD 白名单 / AWAvenue 从主规则移除或移入补充规则)。",
    "一行一个域名;放行语义应覆盖其全部子域名。",
    "收录章程:①全部条目带 issue 溯源;②与两个项目的广告规则发布产物零交集。",
]


def active_domains(st: State) -> list[str]:
    return sorted(d for d, rec in st["domains"].items()
                  if rec.get("status") == "active")


def render_lists(st: State, out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    doms = active_domains(st)
    today = date.today().isoformat()
    with open(os.path.join(out_dir, "merged_false_positive_whitelist.txt"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write(f"# Generated: {today} | Total: {len(doms)}\n")
        f.write("\n".join("# " + h for h in HEADER_NOTE) + "\n")
        f.write("\n".join(doms) + ("\n" if doms else ""))
    with open(os.path.join(out_dir, "merged_false_positive_whitelist_adguard.txt"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write(f"! Generated: {today} | Total: {len(doms)}\n")
        f.write("\n".join("! " + h for h in HEADER_NOTE) + "\n")
        f.write("\n".join(f"@@||{d}^" for d in doms) + ("\n" if doms else ""))
    return doms


def _link(n: int, repo: str) -> str:
    return f"https://github.com/{repo}/issues/{n}"


def render_provenance(st: State, out_dir: str) -> None:
    lines = ["# 误报域名白名单 — 溯源", "",
             f"自动生成于 {date.today().isoformat()};收录标准与判定方法见 README。", "",
             "| 域名 | 来源 | 判定 | issue |", "|---|---|---|---|"]
    for d in active_domains(st):
        rec = st["domains"][d]
        for s in rec["sources"]:
            links = " ".join(f"[#{it['n']}]({_link(it['n'], it.get('repo', s['repo']))})"
                             for it in s.get("issues", [])) or "—"
            kind = s.get("kind")
            if kind == "whitelist-php":
                judge = (f"白名单php(v={s.get('value')}) "
                         + (s.get("comment") or "")[:60]).strip()
            elif kind == "issue-only":
                judge = "issue确认(进复核队列后人工批准) " + (s.get("action") or "")
            elif kind == "manual":
                judge = s.get("action") or "人工批准"
            else:
                judge = ((s.get("action") or "维护者确认") + " "
                         + (s.get("note") or "")).strip()
            lines.append(f"| `{d}` | {s['repo']} | {judge} | {links} |")
    with open(os.path.join(out_dir, "PROVENANCE.md"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


REPO_SHORT = {
    config.ANTIAD: "anti-AD",
    config.AWAVENUE: "AWAvenue",
    "manual": "人工",
}
_TEMPLATE_NOISE = re.compile(r"\[BUG\]\s*<问题标题>|\[BUG\]|\[enhancement\]|\s{2,}")


def _clean_title(title: str | None, limit: int = 60) -> str:
    """Issue titles carry the breakage description; strip template noise."""
    t = _TEMPLATE_NOISE.sub(" ", title or "").strip()
    return t[:limit] + ("…" if len(t) > limit else "")


def _clean_comment(comment: str | None, limit: int = 60) -> str:
    """Maintainer's php annotation; embedded issue refs are printed separately."""
    t = re.sub(r"#\d{2,5}|https?://\S+", "", comment or "").strip(" ,;，;/ ")
    return t[:limit] + ("…" if len(t) > limit else "")


def render_annotated_list(st: State, out_dir: str) -> list[str]:
    """One domain per line with an inline provenance comment:
    `domain  # repo issues(问题;处置) — one segment per source repo`."""
    os.makedirs(out_dir, exist_ok=True)
    # issue title index (titles describe the reported breakage); locked
    # records carry placeholder titles, exclude them
    titles: dict[tuple[str, int], str] = {}
    for repo, issues in st["issues"].items():
        for num, rec in issues.items():
            if rec.get("title") and not rec.get("locked"):
                titles[(repo, int(num))] = rec["title"]

    lines = []
    for d in active_domains(st):
        by_repo: dict[str, list[dict]] = {}
        for s in st["domains"][d]["sources"]:
            if s.get("kind") != "rejected":
                by_repo.setdefault(s["repo"], []).append(s)

        segs = []
        for repo, srcs in by_repo.items():
            nums = sorted({it["n"] for s in srcs for it in s.get("issues", [])})
            iss = "+".join(f"#{n}" for n in nums) or "无issue号"
            kinds = {s.get("kind") for s in srcs}
            php_src = next((s for s in srcs if s.get("kind") == "whitelist-php"), None)
            # problem text: issue title > maintainer php comment > note/action
            problem = ""
            for n in nums:
                t = _clean_title(titles.get((repo, n)))
                if t:
                    problem = t
                    break
            if not problem and php_src:
                problem = _clean_comment(php_src.get("comment"))
            if not problem:
                problem = next((s.get("note") for s in srcs if s.get("note")), "") \
                    or next((s.get("action") for s in srcs if s.get("action")), "")
            if not problem:
                problem = "维护者确认误杀"
            # disposition flags
            flags = []
            if php_src:
                v = php_src.get("value")
                flags.append("php白名单" + ("(含子域)" if v == 1 else ""))
            if "issue-only" in kinds:
                flags.append("复核后人工放行")
            action = next((s.get("action") for s in srcs
                           if s.get("kind") == "issue-confirmed" and s.get("action")), None)
            if action:
                flags.append(action)
            if repo == "manual":
                flags.append("人工批准")
            seg = f"{REPO_SHORT.get(repo, repo)} {iss}({problem}"
            if flags:
                seg += ";" + ";".join(dict.fromkeys(flags))
            seg += ")"
            segs.append(seg)
        lines.append(f"{d}  # " + "; ".join(segs))

    path = os.path.join(out_dir, "whitelist_annotated.txt")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# 误报白名单(带溯源注释) {date.today().isoformat()} | "
                f"Total: {len(lines)}\n")
        f.write("# 格式: 域名  # 仓库 issue号(报告的问题;维护者处置) — 多仓库来源用 ; 分隔\n")
        f.write("\n".join(lines) + ("\n" if lines else ""))
    return lines


def render_noref_reference(st: State, out_dir: str) -> None:
    """anti-AD whitelist entries WITHOUT issue references — reference only,
    never part of the main list (charter rule 1)."""
    noref = st.get("whitelist_php_noref") or {}
    path = os.path.join(out_dir, "antiad_whitelist_without_issue_ref.txt")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# anti-AD 白名单中无 issue 引用的条目({len(noref)} 条)— 仅供参考\n")
        f.write("# 这些是 anti-AD 维护者的内部策展(非 issue 误报产物),不满足本列表\n")
        f.write("# 的收录章程(必须有 issue 溯源)。如需放行请自行取用或加入\n")
        f.write("# data/manual_overrides.json 的 approve。\n")
        for d in sorted(noref):
            cmt = noref[d]
            f.write(f"{d}" + (f"  # {cmt}" if cmt else "") + "\n")


def render_report(st: State, out_dir: str, run_info: dict) -> None:
    os.makedirs(out_dir, exist_ok=True)
    lines = [f"# 运行报告 {run_info['date']}", ""]
    lines.append(f"- API 调用:{run_info['api_calls']}")
    if run_info.get("new_domains"):
        lines.append(f"- 新增域名:{len(run_info['new_domains'])}: "
                     + ", ".join(f"`{d}`" for d in run_info["new_domains"]))
    else:
        lines.append("- 新增域名:0")
    if run_info.get("promoted"):
        lines.append(f"- pending→生效:{len(run_info['promoted'])}: "
                     + ", ".join(f"`{d}`" for d in run_info["promoted"]))
    if run_info.get("approved"):
        lines.append(f"- 人工批准(manual_overrides):{len(run_info['approved'])}: "
                     + ", ".join(f"`{d}`" for d in run_info["approved"]))
    if run_info.get("conflicts"):
        lines.append(f"- **冲突(与广告列表重叠,已剔除出列表)**:{len(run_info['conflicts'])}")
        lines.extend(f"  - `{d}` — {where}" for d, where in run_info["conflicts"])
    php = run_info.get("php_changes") or {}
    if php:
        lines.append(f"- anti-AD 白名单php变更:+{php.get('added', 0)} / "
                     f"-{php.get('removed', 0)} / value变更 {php.get('changed', 0)}"
                     f"(关联 issue:{php.get('commit_issues') or '无'})")
    counts: dict[str, dict[str, int]] = {}
    for r in config.ALL_REPOS:
        counts[r] = {}
        for s in ("done", "rejected", "pending", "no-verdict"):
            counts[r][s] = sum(1 for x in st["issues"][r].values()
                               if x.get("status") == s)
    lines.append(f"- issue 处理计数:{counts}")
    pending = sorted(d for d, rec in st["domains"].items()
                     if rec.get("status") == "pending")
    if pending:
        lines.append(f"- 待人工复核(anti-AD issue 确认但未经白名单php佐证,{len(pending)} 个):")
        for d in pending:
            rec = st["domains"][d]
            iss = sorted({it["n"] for s in rec["sources"] for it in s.get("issues", [])
                          if s["repo"] == config.ANTIAD})
            links = " ".join(f"[#{n}]({_link(n, config.ANTIAD)})" for n in iss)
            lines.append(f"  - `{d}` {links}")
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
