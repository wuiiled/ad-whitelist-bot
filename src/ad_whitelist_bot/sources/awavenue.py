"""AWAvenue source: issue scan + main-rule absence verification.

AWAvenue has no whitelist file — false positives are handled by REMOVING the
domain from the main rule (or moving it to the Replenish/strict layer). A
confirmed fix is therefore verifiable: the domain must be absent from the
current `||domain^` main rule. That makes AWAvenue confirmations strong
enough to auto-activate, unlike anti-AD issue-only confirmations.
"""
from __future__ import annotations

import logging
import re

from .. import config, extract, state as state_mod
from . import base

log = logging.getLogger(__name__)

RELATED_SECTION_RE = re.compile(
    r"相关域名[^\n]*[:：]\s*\n((?:[^\n#>]{2,}\n?){0,20})")


def is_candidate(issue: dict) -> bool:
    title = issue.get("title") or ""
    text = title + "\n" + (issue.get("body") or "")
    # pure domain-submission issues are additions, not false positives
    if re.search(config.SUBMISSION_RE, title, re.I) \
            and not re.search(r"误|\[BUG\]|BUG]", title, re.I):
        return False
    return bool(re.search(config.CANDIDATE_RE, text, re.I))


def domains_from_issue(issue: dict) -> list[str]:
    """Title first, then the template's 相关域名 section, then the whole body."""
    body = issue.get("body") or ""
    picked = extract.extract_domains(issue.get("title"))
    m = RELATED_SECTION_RE.search(body)
    if m:
        picked += extract.extract_domains(m.group(1))
    for d in extract.extract_domains(body):
        if d not in picked:
            picked.append(d)
    return picked


def scan_issues(client, issues: list[dict], st, awavenue_main: set[str],
                full: bool = False) -> dict[str, dict]:
    """Scan AWAvenue issues; returns {domain -> record} for confirmations
    whose domains are verifiably absent from the current main rule."""
    confirmed: dict[str, dict] = {}
    for ev in base.evaluate_issues(client, config.AWAVENUE, issues, st,
                                   is_candidate, full):
        it = ev["issue"]
        num = str(it["number"])
        rec = base.base_issue_record(ev)
        rec["issue_state"] = it["state"]
        if ev["verdict"] == "confirmed" and it["state"] == "closed":
            # confirming comment + the issue's own report (title / 相关域名 /
            # body), filtered by main-rule absence — the effective verification
            mc = extract.extract_domains(ev["verdict_body"])
            picked = [d for d in dict.fromkeys(mc + domains_from_issue(it))
                      if d not in awavenue_main
                      and not extract.suffix_blocked(d, awavenue_main)]
            rec.update(status="done", verdict="confirmed", domains=picked)
            for d in picked:
                confirmed.setdefault(d, {
                    "domain": d,
                    "sources": [{"repo": config.AWAVENUE, "kind": "issue-confirmed",
                                 "issues": [{"n": it["number"], "repo": config.AWAVENUE}],
                                 "action": ev["evidence"] or "maintainer confirmed removal"}]})
        elif ev["verdict"] == "confirmed":
            # maintainer announced the fix but the issue is still open (or the
            # rule has not been rebuilt yet): hold as pending, promote later
            # once the domain verifiably disappears from the main rule.
            rec.update(status="pending", verdict="confirmed",
                       domains=domains_from_issue(it))
        else:
            rec.update(status=base.STATUS_MAP.get(ev["verdict"], "no-verdict"))
        base.record_issue(st, config.AWAVENUE, num, rec)
    return confirmed


def promote_pending(st, awavenue_main: set[str]) -> list[str]:
    """Pending AWAvenue issue records become active once their domains are
    verifiably absent from the main rule (the promised removal happened)."""
    promoted: list[str] = []
    for num, rec in st["issues"][config.AWAVENUE].items():
        if rec.get("status") != "pending" or not rec.get("domains"):
            continue
        still = [d for d in rec["domains"]
                 if d in awavenue_main or extract.suffix_blocked(d, awavenue_main)]
        if still:
            continue
        rec.update(status="done", verdict="confirmed",
                   note="promoted: no longer in main rule")
        for d in rec["domains"]:
            state_mod.merge_domain(st, d, {
                "repo": config.AWAVENUE, "kind": "issue-confirmed",
                "issues": [{"n": int(num), "repo": config.AWAVENUE}],
                "action": "promoted: removed from main rule"})
            promoted.append(d)
    return promoted
