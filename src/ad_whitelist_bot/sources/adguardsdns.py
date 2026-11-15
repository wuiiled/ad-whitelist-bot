"""AdGuard DNS filter source: published-product adjudication harvest.

The AdGuard DNS filter (the f1 product) ships two adjudication files:
- Filters/exclusions.txt  — domains REMOVED from the built filter (the
  maintainer applied the fix): bare `||domain^` rules, AWAvenue-removal
  semantics, auto-activatable;
- Filters/exceptions.txt  — `@@||domain^|` exemptions INJECTED into the
  built filter (parent still blocked, subdomain carved out).

Both carry `! <issue url>` annotation lines. An annotation block binds to
every consecutive rule line that follows it (cleared by the next `!` block
or a blank line); `!` lines without URLs are explanatory and keep the
current block. Entries without any issue reference go to the noref bucket
and never enter the main list (charter rule 1).

Charter semantics for this source (per-source zero-intersection, gate-
measured 2026-11-15): a domain sourced here must not appear as an EXACT
block rule in the published filter (ancestor hits are expected for
exceptions and only annotated). Cross-source disagreement is recorded by
refresh_cross_status, not conflicted.
"""
from __future__ import annotations

import logging
import re

from .. import config, extract

log = logging.getLogger(__name__)

ISSUE_URL_RE = re.compile(r"([\w.-]+(?:/[\w.-]+)*?)/issues/(\d+)")


def _issue_refs(line: str) -> list[dict]:
    refs = []
    for a, b in ISSUE_URL_RE.findall(line):
        repo = re.sub(r"^(?:www\.)?github\.com/", "", a)
        refs.append({"n": int(b),
                     "repo": None if repo == config.ADG_DNS else repo})
    return refs


def annotated_rules(text: str, rule_fn):
    """Block-level binding: one annotation block covers the run of rule
    lines following it. Yields (domain, issues, note). Shared with the
    referral source, which re-scans the exceptions file for the entries
    this harvest leaves un-annotated."""
    refs: list[dict] = []
    notes: list[str] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            refs, notes = [], []  # 空行清空
            continue
        if s.startswith("!"):
            new_refs = _issue_refs(s)
            if new_refs:
                refs, notes = new_refs, []  # 新注释块:清旧立新
            else:
                notes.append(s.lstrip("! ").strip())  # 块内补充说明行
            continue
        dom = rule_fn(s)
        if dom:
            issues = [{"n": r["n"], "repo": r["repo"] or config.ADG_DNS}
                      for r in refs]
            yield dom, issues, "; ".join(notes)


def _harvest(text: str, kind: str, rule_fn) -> tuple[dict[str, dict], dict[str, str]]:
    records: dict[str, dict] = {}
    noref: dict[str, str] = {}
    for dom, issues, note in annotated_rules(text, rule_fn):
        if issues:
            src = {"repo": config.ADG_DNS, "kind": kind,
                   "action": note or ("maintainer removed from filter"
                                      if kind == "dns-exclusion"
                                      else "maintainer exempted subdomain"),
                   "issues": issues}
            rec = records.setdefault(dom, {"domain": dom, "sources": []})
            if src not in rec["sources"]:
                rec["sources"].append(src)
        else:
            noref[dom] = note
    return records, noref


def harvest_exclusions(text: str) -> tuple[dict[str, dict], dict[str, str]]:
    return _harvest(text, "dns-exclusion", extract.parse_rule_domain_line)


def harvest_exceptions(text: str) -> tuple[dict[str, dict], dict[str, str]]:
    return _harvest(text, "dns-exception", extract.parse_allow_rule_domain_line)


def harvest(exclusions_text: str,
            exceptions_text: str) -> tuple[dict[str, dict], dict[str, str]]:
    """Merge both files; a domain appearing in both carries two sources.
    Returns (records, noref)."""
    records: dict[str, dict] = {}
    noref: dict[str, str] = {}
    for harvest_fn, text in ((harvest_exclusions, exclusions_text),
                             (harvest_exceptions, exceptions_text)):
        rec, nore = harvest_fn(text)
        for d, r in rec.items():
            tgt = records.setdefault(d, {"domain": d, "sources": []})
            for s in r["sources"]:
                if s not in tgt["sources"]:
                    tgt["sources"].append(s)
        noref.update(nore)
    return records, noref
