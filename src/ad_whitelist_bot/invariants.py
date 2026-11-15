"""Charter invariants enforced on every run.

Hard rule: no output domain may be present in either published ad list.
- anti-AD: exact presence in anti-ad-domains.txt -> conflict.
  (Ancestor entries are handled by anti-AD's own @@ whitelist rules;
  they are recorded as informational `partial_block`, not conflicts.)
- AWAvenue: exact or ancestor `||rule^` in the main rule -> conflict
  (AdGuard suffix semantics block the domain in every consumer).

The invariant applies regardless of which project sourced the entry, and
regardless of any manual approval — a human decision cannot make a domain
"not blocked" upstream. Conflicts are re-checked every run: when the
upstream block disappears, the record recovers — `active` if it still
carries qualifying evidence (has_active_backing), else `pending` (back to
the human review queue, matching the issue-only charter rule).
"""
from __future__ import annotations

import logging

from . import config, extract
from .state import State, now_iso

log = logging.getLogger(__name__)


def has_active_backing(rec: dict) -> bool:
    """True if the record still carries evidence that justifies `active`."""
    if rec.get("approved_by") == "manual_overrides":
        return True
    for s in rec.get("sources", []):
        if s.get("kind") == "issue-confirmed":
            return True
        if s.get("kind") == "whitelist-php" and not s.get("php_removed"):
            return True
    return False


def enforce_invariants(st: State, awavenue_main: set[str],
                       antiad_block: set[str]) -> tuple[list[tuple[str, str]],
                                                        list[tuple[str, str]]]:
    """Flip violating active domains to `conflict`; recover stale conflicts.

    Returns (conflicts, recovered):
    - conflicts: [(domain, where)] for NEW conflicts (active -> conflict);
      already-conflicted domains are silently re-confirmed.
    - recovered: [(domain, target)] for conflicts lifted this run
      (target = "active" with qualifying evidence, else "pending").
    """
    conflicts: list[tuple[str, str]] = []
    recovered: list[tuple[str, str]] = []
    for d, rec in st["domains"].items():
        status = rec.get("status")
        if status not in ("active", "conflict"):
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
            if status == "active":
                conflicts.append((d, where))
                log.info("conflict: %s -> %s", d, where)
            continue
        if status == "conflict":
            target = "active" if has_active_backing(rec) else "pending"
            rec["status"] = target
            rec.pop("conflict", None)
            recovered.append((d, target))
            log.info("conflict resolved: %s -> %s", d, target)
            if target != "active":
                continue  # pending domains need no partial_block bookkeeping
        if any(s["repo"] == config.ANTIAD for s in rec["sources"]) \
                and extract.suffix_blocked(d, antiad_block):
            rec["partial_block"] = "ancestor blocked in anti-ad-domains.txt"
        else:
            rec.pop("partial_block", None)
    return conflicts, recovered


def refresh_cross_status(st: State, awavenue_main: set[str], antiad_block: set[str]) -> None:
    """Non-decisive cross-list status flags, for provenance/debugging."""
    for d, rec in st["domains"].items():
        rec["in_awavenue_main_now"] = d in awavenue_main
        rec["in_antiad_block_now"] = extract.suffix_blocked(d, antiad_block)
