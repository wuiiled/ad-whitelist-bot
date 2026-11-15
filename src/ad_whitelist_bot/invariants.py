"""Charter invariants enforced on every run.

Hard rule: an output domain must not be present in the published block
product of the project that endorsed it (PER-SOURCE zero-intersection).
- anti-AD entries: exact presence in anti-ad-domains.txt -> conflict;
  ancestor -> informational `partial_block` (anti-AD @@ whitelist semantics).
- AWAvenue entries: exact or ancestor `||rule^` in the main rule -> conflict
  (AdGuard suffix semantics block the domain in every consumer).
- AdGuard DNS filter entries: exact presence in the published filter's
  block rules -> conflict; ancestor -> informational note (exceptions
  domains naturally sit under blocked parents).
- manual approvals (no source repo) are checked against ALL products —
  a human decision cannot make a domain "not blocked" upstream.

Cross-source disagreement (project A endorses, project B blocks) is NOT a
conflict: it is recorded per-domain by refresh_cross_status. The gate
measurement (2026-11-15) showed a global rule would destroy 295/630 of the
AdGuard source's value (236 exact + 59 ancestor hits vs anti-AD alone) and
conflict 21 existing entries — those are stance differences between
projects, not adjudication reversals.

Conflicts are re-checked every run: when the upstream block disappears, the
record recovers — `active` if it still carries qualifying evidence
(has_active_backing), else `pending` (back to the human review queue,
matching the issue-only charter rule).
"""
from __future__ import annotations

import logging

from . import config, extract
from .state import State, now_iso

log = logging.getLogger(__name__)

_REPO_BLOCK = {config.ANTIAD: "antiad", config.AWAVENUE: "awavenue",
               config.ADG_DNS: "adguard"}

# Curated referral sources carry no adjudication of their own: they neither
# add block products to check against nor tighten the keys of records that
# also carry traced evidence (a php-backed domain stays php-keyed even if
# Cats also allows it). A record backed ONLY by referral kinds has no
# adjudication regime to contradict, so it is checked against nothing.
_REFERRAL_KINDS = frozenset({"referral"})


def has_active_backing(rec: dict) -> bool:
    """True if the record still carries evidence that justifies `active`."""
    if rec.get("approved_by") == "manual_overrides":
        return True
    for s in rec.get("sources", []):
        if s.get("kind") in ("issue-confirmed", "dns-exclusion", "dns-exception",
                             "referral"):
            return True
        if s.get("kind") == "whitelist-php" and not s.get("php_removed"):
            return True
    return False


def _checked_keys(rec: dict) -> tuple[str, ...]:
    """Which block products this record must be absent from.

    Determined by the record's own traced source repos (per-source zero-
    intersection); manual-only records get the strictest set (all products);
    referral-only records get none (see _REFERRAL_KINDS).
    """
    kinds = {s.get("kind") for s in rec.get("sources", [])
             if s.get("kind") != "rejected"}
    if kinds and kinds <= _REFERRAL_KINDS:
        return ()
    repos = {s.get("repo") for s in rec.get("sources", [])
             if s.get("kind") not in (_REFERRAL_KINDS | {"rejected"})}
    if not repos or "manual" in repos:
        return ("antiad", "awavenue", "adguard")
    return tuple({_REPO_BLOCK[r] for r in repos if r in _REPO_BLOCK})


def enforce_invariants(st: State, awavenue_main: set[str], antiad_block: set[str],
                       adguard_block: set[str] | None = None,
                       adguard_allow: set[str] | None = None,
                       ) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Flip violating active domains to `conflict`; recover stale conflicts.

    `adguard_allow` = the published filter's own @@ exception set: a domain
    carrying its own exemption is NOT blocked by the published product (the
    exceptions mechanism injects @@ precisely to un-block it), so it must
    not conflict. Without this, ~26 exceptions-sourced entries are wrongly
    purged on every run.

    Returns (conflicts, recovered):
    - conflicts: [(domain, where)] for NEW conflicts (active -> conflict);
      already-conflicted domains are silently re-confirmed.
    - recovered: [(domain, target)] for conflicts lifted this run
      (target = "active" with qualifying evidence, else "pending").
    """
    adguard_block = adguard_block or set()
    adguard_allow = adguard_allow or set()
    conflicts: list[tuple[str, str]] = []
    recovered: list[tuple[str, str]] = []
    for d, rec in st["domains"].items():
        status = rec.get("status")
        if status not in ("active", "conflict"):
            continue
        keys = _checked_keys(rec)
        where = None
        if "antiad" in keys and d in antiad_block:
            where = "anti-ad-domains.txt (exact)"
        if "awavenue" in keys and (d in awavenue_main
                                   or extract.suffix_blocked(d, awavenue_main)):
            where = (where + " + " if where else "") + "AWAvenue main rule"
        if "adguard" in keys and d in adguard_block and d not in adguard_allow:
            where = (where + " + " if where else "") + "AdGuard DNS filter (exact)"
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
                continue  # pending domains need no bookkeeping below
        # informational ancestor notes, scoped to each source's own product
        if any(s["repo"] == config.ANTIAD for s in rec["sources"]) \
                and extract.suffix_blocked(d, antiad_block):
            rec["partial_block"] = "ancestor blocked in anti-ad-domains.txt"
        else:
            rec.pop("partial_block", None)
        if any(s["repo"] == config.ADG_DNS for s in rec["sources"]) \
                and extract.suffix_blocked(d, adguard_block):
            rec["adguard_ancestor_block"] = \
                "ancestor blocked in published AdGuard DNS filter"
        else:
            rec.pop("adguard_ancestor_block", None)
    return conflicts, recovered


def refresh_cross_status(st: State, awavenue_main: set[str], antiad_block: set[str],
                         adguard_block: set[str] | None = None) -> None:
    """Non-decisive cross-list status flags, for provenance/debugging.

    Cross-source disagreement is recorded here (soft), never conflicted."""
    adguard_block = adguard_block or set()
    for d, rec in st["domains"].items():
        rec["in_awavenue_main_now"] = d in awavenue_main
        rec["in_antiad_block_now"] = extract.suffix_blocked(d, antiad_block)
        rec["in_adguard_filter_now"] = extract.suffix_blocked(d, adguard_block)
