"""anti-AD source: live whitelist-php harvest + issue scan.

The authoritative exclusion list is the whitelist php on the adlist-maker
branch (scripts/lib/white_domain_list.php), maintained by MkQtS with `fix #N`
commit messages. Only entries WITH issue provenance (comment references, or
commit-message attribution) enter the main list; entries without references
are tracked separately as a reference file (see render.render_noref_reference).
"""
from __future__ import annotations

import logging
import re

from .. import config, extract, verdict
from . import base

log = logging.getLogger(__name__)

ISSUE_REF_RE = re.compile(
    r"([\w.-]+(?:/[\w.-]+)*?)/issues/(\d+)|(?<![#&\w])#(\d{2,5})\b")


# ------------------------------------------------------------ whitelist php
def parse_white_php(text: str) -> list[dict]:
    """Parse white_domain_list.php into entries.

    value semantics: 0 = exact domain whitelisted, 1 = domain + all children,
    -1 = whitelist entry disabled (excluded everywhere).
    """
    entries = []
    for i, line in enumerate(text.splitlines()):
        s = line.strip()
        if s.startswith("//"):
            continue  # commented-out entry
        m = re.match(r'"([^"]+)"\s*=>\s*(-?\d+)\s*,?\s*(.*)$', s)
        if not m:
            continue
        dom, val = m.group(1).lower(), int(m.group(2))
        tail = m.group(3).lstrip("/").lstrip("/")
        comment = tail[2:].strip() if tail.startswith("//") else tail.strip()
        refs: list[tuple[int, str | None]] = []
        for a, b, c in ISSUE_REF_RE.findall(tail):
            if a:  # full URL form — may point at another repo (e.g. nextdns/metadata)
                repo = re.sub(r"^(?:www\.)?github\.com/", "", a)  # strip host prefix
                refs.append((int(b), None if repo == config.ANTIAD else repo))
            else:
                refs.append((int(c), None))
        entries.append({"domain": dom, "value": val, "comment": comment,
                        "line": i + 1, "refs": refs})
    return entries


def harvest_white_php(php_text: str) -> tuple[dict[str, dict], dict[str, str]]:
    """Split active php entries by provenance.

    Returns (records, noref):
      records — {domain -> {sources: [...]}} for entries WITH issue refs;
      noref   — {domain -> comment} for active entries without refs.
                These never enter the main list (charter rule 1).
    """
    records: dict[str, dict] = {}
    noref: dict[str, str] = {}
    for e in parse_white_php(php_text):
        if e["value"] == -1:
            continue
        if e["refs"]:
            issues = [{"n": n, "repo": repo or config.ANTIAD} for n, repo in e["refs"]]
            rec = records.setdefault(e["domain"], {"domain": e["domain"], "sources": []})
            src = {"repo": config.ANTIAD, "kind": "whitelist-php",
                   "value": e["value"], "comment": e["comment"], "issues": issues}
            if src not in rec["sources"]:
                rec["sources"].append(src)
        else:
            noref[e["domain"]] = e["comment"]
    return records, noref


def commit_issue_refs(client, since_iso: str | None) -> list[int]:
    """Issue numbers cited in recent whitelist-php commit messages (`fix #N`)."""
    if not since_iso:
        return []
    try:
        commits = client.commits(config.ANTIAD, "adlist-maker",
                                 "scripts/lib/white_domain_list.php", since_iso)
    except Exception as exc:  # noqa: BLE001 - never fail a run over attribution
        log.warning("commit fetch failed: %s", exc)
        return []
    nums: list[int] = []
    for c in commits:
        nums.extend(int(n) for n in re.findall(r"#(\d{2,5})", c["commit"]["message"]))
    return sorted(set(nums))


# -------------------------------------------------------------- issue scan
def is_candidate(issue: dict) -> bool:
    title = issue.get("title") or ""
    text = title + "\n" + (issue.get("body") or "")
    if re.search(config.SUBMISSION_RE, title, re.I) \
            and not re.search(r"误|\[BUG\]|BUG]", title, re.I):
        return False
    return bool(re.search(config.CANDIDATE_RE, text, re.I))


def scan_issues(client, issues: list[dict], st, full: bool = False) -> dict[str, dict]:
    """Scan anti-AD issues; returns {domain -> record} for issue-only
    confirmations. These land in the human review queue (status pending) —
    the whitelist php is the authoritative exclusion list, and free-text
    confirmations need a human eye (see state.apply_overrides).
    """
    issue_only: dict[str, dict] = {}
    for ev in base.evaluate_issues(client, config.ANTIAD, issues, st,
                                   is_candidate, full):
        it = ev["issue"]
        num = str(it["number"])
        rec = base.base_issue_record(ev)
        if ev["verdict"] == "confirmed":
            # Domains attributed to the confirming comment plus the issue
            # TITLE only — body-wide extraction harvests unrelated domains
            # from mass reports; anything truly whitelisted ends up in the
            # php and is covered by the harvest anyway.
            title_d = extract.extract_domains(it.get("title"))
            mc = extract.extract_domains(ev["verdict_body"])
            picked = list(dict.fromkeys(mc + title_d))
            rec.update(status="done", verdict="confirmed", domains=picked)
            for d in picked:
                issue_only.setdefault(d, {
                    "domain": d,
                    "sources": [{"repo": config.ANTIAD, "kind": "issue-only",
                                 "issues": [{"n": it["number"], "repo": config.ANTIAD}],
                                 "action": ev["evidence"] or "maintainer confirmed"}]})
        else:
            rec.update(status=base.STATUS_MAP.get(ev["verdict"], "no-verdict"))
        base.record_issue(st, config.ANTIAD, num, rec)
    return issue_only
