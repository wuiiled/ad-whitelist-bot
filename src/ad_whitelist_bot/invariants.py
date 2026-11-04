"""Charter invariants enforced on every run.

Hard rule: no output domain may be present in either published ad list.
- anti-AD: exact presence in anti-ad-domains.txt -> conflict.
  (Ancestor entries are handled by anti-AD's own @@ whitelist rules;
  they are recorded as informational `partial_block`, not conflicts.)
- AWAvenue: exact or ancestor `||rule^` in the main rule -> conflict
  (AdGuard suffix semantics block the domain in every consumer).

The invariant applies regardless of which project sourced the entry, and
regardless of any manual approval — a human decision cannot make a domain
"not blocked" upstream.
"""
from __future__ import annotations

import logging

from . import config, extract
from .state import State, now_iso

log = logging.getLogger(__name__)


def enforce_invariants(st: State, awavenue_main: set[str], antiad_block: set[str]) -> list[tuple[str, str]]:
    """Flip violating active domains to `conflict`; returns [(domain, where)]."""
    conflicts: list[tuple[str, str]] = []
    for d, rec in st["domains"].items():
        if rec.get("status") != "active":
            continue
        where = None
        if d in antiad_block:
            where = "anti-ad-domains.txt (exact)"
        if d in awavenue_main or extract.suffix_blocked(d, awavenue_main):
            where = (where + " + " if where else "") + "AWAvenue main rule"
        if where:
            rec["status"] = "conflict"
            rec["conflict"] = {"where": where, "detected": now_iso()}
            rec.pop("partial_block", None)
            conflicts.append((d, where))
            log.info("conflict: %s -> %s", d, where)
            continue
        if any(s["repo"] == config.ANTIAD for s in rec["sources"]) \
                and extract.suffix_blocked(d, antiad_block):
            rec["partial_block"] = "ancestor blocked in anti-ad-domains.txt"
        else:
            rec.pop("partial_block", None)
    return conflicts


def refresh_cross_status(st: State, awavenue_main: set[str], antiad_block: set[str]) -> None:
    """Non-decisive cross-list status flags, for provenance/debugging."""
    for d, rec in st["domains"].items():
        rec["in_awavenue_main_now"] = d in awavenue_main
        rec["in_antiad_block_now"] = extract.suffix_blocked(d, antiad_block)
