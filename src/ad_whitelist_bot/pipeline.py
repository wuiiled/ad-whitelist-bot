"""Pipeline orchestration: `seed` (build initial state) and `run` (daily update)."""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

from . import config, extract, invariants, render, state
from .github import GitHubClient
from .sources import adguardsdns, antiad, awavenue, referral
from .state import State, now_iso

log = logging.getLogger(__name__)


def _snapshot(st: State) -> dict:
    """Content snapshot of everything that determines rendered artifacts.

    active/pending/noref determine which domains appear in the outputs;
    active domains' serialized sources cover provenance edits (php value or
    comment changes, re-adds clearing php_removed, extra issue confirmations)
    that alter whitelist_annotated.txt / PROVENANCE.md without moving domains.
    """
    return {
        "active": set(render.active_domains(st)),
        "pending": {d for d, r in st["domains"].items()
                    if r.get("status") == "pending"},
        "noref": dict(st.get("whitelist_php_noref") or {}),
        "srcs": {d: sorted(json.dumps(s, sort_keys=True, ensure_ascii=False)
                           for s in r.get("sources", []))
                 for d, r in st["domains"].items()
                 if r.get("status") == "active"},
    }


def _substantive(before: dict, after: dict) -> bool:
    """True if any rendered artifact (beyond generated dates) would differ."""
    return any(before[k] != after[k] for k in before)


def _annotate_php_removals(st: State, removed: list[str], date: str) -> list[str]:
    """Stamp php_removed on sources; demote unbacked active domains to pending.

    A php whitelist entry disappearing revokes anti-AD's endorsement; domains
    without other qualifying evidence (AWAvenue issue-confirmed / manual
    approval) go back to the review queue. Returns demoted domains.
    """
    demoted: list[str] = []
    for d in removed:
        rec = st["domains"].get(d)
        if not rec:
            continue
        for s in rec["sources"]:
            if s.get("kind") == "whitelist-php":
                s["php_removed"] = date
        if rec["status"] == "active" and not invariants.has_active_backing(rec):
            rec["status"] = "pending"
            demoted.append(d)
            log.info("php removed without backing: %s -> pending", d)
    return demoted


def _fetch_artifacts(client: GitHubClient) -> tuple[str, set[str], set[str]]:
    """Fetch the three live artifacts: whitelist php, anti-AD blocklist,
    AWAvenue main rule."""
    php = client.get_raw(config.ANTIAD_WHITE_PHP_URL)
    antiad_block = extract.parse_domain_blocklist(client.get_raw(config.ANTIAD_BLOCK_URL))
    awavenue_main = extract.parse_adguard_rule_domainset(client.get_raw(config.AWAVENUE_RULE_URL))
    log.info("artifacts: anti-ad block=%d domains, awavenue rule=%d domains",
             len(antiad_block), len(awavenue_main))
    return php, antiad_block, awavenue_main


def _reapply_rejection_seeds(st: State) -> list[str]:
    """Re-assert seed_rejections.json verdicts every run.

    The rejection layer is a sticky human decision (maintainer explicitly
    keeps these blocked), but seeds were only applied at seed-time — a
    record that drifted out of `rejected` would sit in the list unchecked.
    Found by the 2026-11-15 per-domain audit: security.snssdk.com shipped
    active for its whole life. Returns re-fixed domains.
    """
    rej = state.load_seed_json("seed_rejections.json")
    if not rej:
        return []
    fixed: list[str] = []
    for item in rej["domains"]:
        rec = st["domains"].get(item["domain"])
        if rec and rec.get("status") != "rejected":
            rec["status"] = "rejected"
            fixed.append(item["domain"])
            log.info("rejection seed re-asserted: %s", item["domain"])
    return fixed


def _fetch_adguard(client: GitHubClient) -> tuple[dict[str, dict], dict[str, str],
                                                  set[str], set[str], str]:
    """AdGuard DNS filter adjudication files + published product sets.

    Returns (records, noref, block, allow, exceptions_text) — allow = the
    published filter's own @@ exception set; a domain carrying its own
    exemption is not blocked by the published product and must not conflict.
    exceptions_text is passed through for the referral source, which harvests
    the un-annotated remainder (one fetch, two consumers).
    """
    excl = client.get_raw(config.ADG_DNS_EXCLUSIONS_URL)
    exc = client.get_raw(config.ADG_DNS_EXCEPTIONS_URL)
    filt = client.get_raw(config.ADG_DNS_FILTER_URL)
    records, noref = adguardsdns.harvest(excl, exc)
    block = extract.parse_adguard_rule_domainset(filt)
    allow = {d for ln in filt.splitlines()
             if (d := extract.parse_allow_rule_domain_line(ln))}
    log.info("adguard artifacts: harvested=%d domains, noref=%d, "
             "published filter block=%d allow=%d", len(records), len(noref),
             len(block), len(allow))
    return records, noref, block, allow, exc


def _fetch_referral(client: GitHubClient) -> tuple[str, str]:
    """Curated referral feed files (Cats-Team/AdRules, local anudeepND snapshot)."""
    cats = client.get_raw(config.CATS_ALLOWLIST_URL)
    if os.path.exists(config.ANUDEEP_WHITELIST_PATH):
        with open(config.ANUDEEP_WHITELIST_PATH, encoding="utf-8") as f:
            anudeep = f.read()
    else:
        anudeep = client.get_raw(config.ANUDEEP_WHITELIST_URL)
    log.info("referral artifacts: cats=%d bytes, anudeep=%d bytes",
             len(cats), len(anudeep))
    return cats, anudeep


def _referral_live_sets(cats_text: str, anudeep_text: str,
                        exceptions_text: str, traced_exceptions: set[str],
                        ) -> dict[str, set[str]]:
    """Per-feed live domain sets for liveness marking. Re-parses the three
    small texts (build_records keeps its single-map signature)."""
    return {
        config.CATS: set(referral.harvest_cats(cats_text)),
        config.ANUDEEP: set(referral.harvest_anudeep(anudeep_text)),
        config.ADG_DNS: set(referral.harvest_exceptions_noref(
            exceptions_text, traced_exceptions)),
    }


def _guard_referral_feeds(st: State, live: dict[str, set[str] | None]) -> None:
    """A feed that comes back empty or collapses against the bot's own memory
    is a fetch anomaly, not a mass retirement: skip liveness marking for it —
    one bad fetch must never silently retire a whole curated layer (mirror of
    the consumer's stale-cache refusal to synthesize from suspicious data)."""
    for repo, feed in live.items():
        if feed is None:
            continue
        prev = sum(1 for r in st["domains"].values()
                   for s in r.get("sources", [])
                   if s.get("kind") == "referral" and s.get("repo") == repo
                   and not s.get("referral_removed"))
        if not feed:
            log.warning("referral feed %s came back empty — liveness marking "
                        "skipped for this feed", repo)
            live[repo] = None
        elif prev and len(feed) * 2 < prev:
            log.warning("referral feed %s collapsed (%d live vs ~%d backed in "
                        "state) — liveness marking skipped for this feed",
                        repo, len(feed), prev)
            live[repo] = None


def _annotate_referral_removals(st: State, live: dict[str, set[str] | None],
                                date: str) -> list[str]:
    """Liveness reconciliation, per referral source: stamp `referral_removed`
    on sources absent from this run's feed (keeping the first retirement
    date), and CLEAR the flag from sources their feed carries again — before
    `merge_referral` runs, so a re-added domain's source dict compares equal
    and never duplicates (dual-backed actives never enter the demotion path,
    so the pending-only closure would miss them). Then demote unbacked
    actives to the review queue (mirror of _annotate_php_removals). Returns
    demoted domains."""
    demoted: list[str] = []
    for d, rec in st["domains"].items():
        for s in rec.get("sources", []):
            if s.get("kind") != "referral":
                continue
            feed = live.get(s.get("repo"))
            if feed is None:  # guard-disabled feed: leave flags untouched
                continue
            if d not in feed:
                s.setdefault("referral_removed", date)
            else:
                s.pop("referral_removed", None)
        if rec.get("status") == "active" \
                and not invariants.has_active_backing(rec) \
                and any(s.get("referral_removed")
                        for s in rec.get("sources", [])):
            rec["status"] = "pending"
            rec["demoted_by"] = "referral-removal"
            demoted.append(d)
            log.info("referral removed without backing: %s -> pending", d)
    return demoted


def _merge_referral(st: State, cats_text: str, anudeep_text: str,
                    exceptions_text: str, traced_exceptions: set[str],
                    date: str,
                    ) -> tuple[list[str], list[str], list[str]]:
    """Consolidate the curated consumer feeds (2026-11-16 migration).

    Returns (added, suppressed, demoted).
    """
    cats_rec = referral.harvest_cats(cats_text)
    anudeep_rec = referral.harvest_anudeep(anudeep_text)
    exc_rec = referral.harvest_exceptions_noref(exceptions_text, traced_exceptions)
    live: dict[str, set[str] | None] = {
        config.CATS: set(cats_rec),
        config.ANUDEEP: set(anudeep_rec),
        config.ADG_DNS: set(exc_rec),
    }
    _guard_referral_feeds(st, live)
    demoted = _annotate_referral_removals(st, live, date)
    records = referral.merge_harvested_records([cats_rec, anudeep_rec, exc_rec])
    added, suppressed = state.merge_referral(st, records)
    log.info("referral merge: +%d added, %d suppressed, %d demoted",
             len(added), len(suppressed), len(demoted))
    return added, suppressed, demoted


def _referral_stance_conflicts(st: State, antiad_block: set[str],
                               awavenue_main: set[str]) -> list[str]:
    """Referral-only active domains the CN block products exactly block.

    Cross-source stance disagreement, not a charter conflict (the referral
    feeds have no block product of their own); reported so the maintainer
    can deny individual entries via manual_overrides.
    """
    out = []
    for d, rec in st["domains"].items():
        if rec.get("status") != "active":
            continue
        kinds = {s.get("kind") for s in rec["sources"]}
        if not kinds or not kinds <= invariants.REFERRAL_KINDS:
            continue
        if d in antiad_block or d in awavenue_main:
            out.append(d)
    return sorted(out)


def seed() -> None:
    """Build data/state.json from the live whitelist php + human-audit seeds."""
    client = GitHubClient()
    st = state.empty_state()
    php, antiad_block, awavenue_main = _fetch_artifacts(client)

    php_entries = antiad.parse_white_php(php)
    records, noref = antiad.harvest_white_php(php, entries=php_entries)
    state.merge_records(st, records)
    st["whitelist_php_noref"] = noref
    st["whitelist_php_snapshot"] = {e["domain"]: e["value"]
                                    for e in php_entries
                                    if e["value"] != -1}

    adguard_records, _, adguard_block, adguard_allow, adg_exc = _fetch_adguard(client)
    state.merge_records(st, adguard_records)
    cats_text, anudeep_text = _fetch_referral(client)
    traced_exceptions = {d for d, r in adguard_records.items()
                         if any(s.get("kind") == "dns-exception"
                                for s in r["sources"])}
    added, suppressed, _ = _merge_referral(st, cats_text, anudeep_text,
                                           adg_exc, traced_exceptions,
                                           now_iso()[:10])
    log.info("seed referral: +%d added, %d suppressed", len(added), len(suppressed))

    seed = state.load_seed_json("seed_awavenue_manual.json")
    if seed:
        for item in seed["domains"]:
            state.merge_domain(st, item["domain"], {
                "repo": config.AWAVENUE, "kind": "issue-confirmed", "audited": True,
                "action": item["action"], "note": item.get("note", ""),
                "issues": [{"n": item["issue"], "repo": config.AWAVENUE}]})
        for num in seed.get("lock_issues", []):
            st["issues"][config.AWAVENUE][str(num)] = {
                "status": "done", "locked": True,
                "title": "human-audited 2026-11-05"}

    rej = state.load_seed_json("seed_rejections.json")
    if rej:
        for item in rej["domains"]:
            rec = state.merge_domain(st, item["domain"], {
                "repo": item["repo"], "kind": "rejected",
                "action": "rejected", "note": item["reason"],
                "issues": [{"n": item["issue"], "repo": item["repo"]}]})
            rec["status"] = "rejected"
        for repo, nums in rej.get("lock_issues", {}).items():
            for num in nums:
                st["issues"][repo][str(num)] = {
                    "status": "rejected", "locked": True,
                    "title": "human-audited rejection 2026-11-05"}

    state.apply_overrides(st)
    _reapply_rejection_seeds(st)
    invariants.enforce_invariants(st, awavenue_main, antiad_block,
                                  adguard_block, adguard_allow)
    invariants.refresh_cross_status(st, awavenue_main, antiad_block, adguard_block)
    state.save(st)
    log.info("seeded: %d domain records, %d active",
             len(st["domains"]), len(render.active_domains(st)))


def run(full: bool = False) -> None:
    """One pipeline pass: harvest -> scan -> promote -> overrides -> invariants -> render."""
    client = GitHubClient()
    st = state.load()
    run_start = datetime.now(timezone.utc).strftime(config.GITHUB_TS_FMT)
    run_info: dict = {"date": run_start[:10], "api_calls": 0,
                      "new_domains": [], "promoted": [], "conflicts": []}

    # ---- 0. substantive-output snapshot (P0-3) -------------------------------
    before = _snapshot(st)

    php, antiad_block, awavenue_main = _fetch_artifacts(client)

    # ---- 1. whitelist-php harvest (issue-provenance entries only) ----------
    php_entries = antiad.parse_white_php(php)
    records, noref = antiad.harvest_white_php(php, entries=php_entries)
    snapshot = {e["domain"]: e["value"] for e in php_entries
                if e["value"] != -1}
    log.info("php entries: %d active", len(snapshot))
    old_snap = st.get("whitelist_php_snapshot", {})
    added = [d for d in snapshot if d not in old_snap]
    removed = [d for d in old_snap if d not in snapshot]
    changed = [d for d in snapshot if d in old_snap and snapshot[d] != old_snap[d]]
    commit_issues = antiad.commit_issue_refs(
        client, st["checkpoints"][config.ANTIAD]) if (added or changed) else []
    if added or removed or changed:
        # re-added entries: clear stale php_removed BEFORE merging — the fresh
        # source dict != the stamped old one, so merging first would append a
        # duplicate that survives the cleanup
        for d in added:
            rec = st["domains"].get(d)
            if rec:
                for s in rec["sources"]:
                    if s.get("kind") == "whitelist-php":
                        s.pop("php_removed", None)
        # no-ref additions attributed via commit messages become ref'd entries
        for d in added:
            if d in records or not commit_issues:
                continue
            records[d] = {"domain": d, "sources": [{
                "repo": config.ANTIAD, "kind": "whitelist-php",
                "value": snapshot[d], "comment": noref.get(d, ""),
                "issues": [{"n": n, "repo": config.ANTIAD} for n in commit_issues],
                "attributed_by": "commit-message"}]}
        merge_new = state.merge_records(st, records)
        run_info["new_domains"].extend(
            d for d in merge_new if st["domains"][d]["status"] == "active")
        demoted = _annotate_php_removals(st, removed, run_info["date"])
        if demoted:
            run_info["php_demoted"] = demoted
        log.info("php changed: +%d/-%d/~%d (commit issues: %s)",
                 len(added), len(removed), len(changed), commit_issues[:10])
    st["whitelist_php_noref"] = {d: c for d, c in noref.items() if d not in records}
    st["whitelist_php_snapshot"] = snapshot
    run_info["php_changes"] = {"added": len(added), "removed": len(removed),
                               "changed": len(changed),
                               "commit_issues": commit_issues[:20]}

    # ---- 1.5 AdGuard DNS filter harvest (file provenance) --------------------
    adguard_records, adguard_noref, adguard_block, adguard_allow, adg_exc = \
        _fetch_adguard(client)
    merge_adg = state.merge_records(st, adguard_records)
    run_info["new_domains"].extend(
        d for d in merge_adg if st["domains"][d]["status"] == "active")
    if adguard_noref:
        log.info("adguard noref (reference-only): %d entries", len(adguard_noref))
    cats_text, anudeep_text = _fetch_referral(client)
    traced_exceptions = {d for d, r in adguard_records.items()
                         if any(s.get("kind") == "dns-exception"
                                for s in r["sources"])}

    # ---- 2. issue scans -----------------------------------------------------
    since_aa = None if full else st["checkpoints"][config.ANTIAD]
    aa_issues = client.all_issues(config.ANTIAD, since=since_aa)
    issue_only = antiad.scan_issues(client, aa_issues, st, full=full)
    for d, rec in issue_only.items():
        state.merge_records(st, {d: rec})
        domain_rec = st["domains"][d]
        # anti-AD issue-only confirmations go to the review queue, never
        # straight into the list; domains already backed by another qualifying
        # source or manual_overrides are preserved as active.
        if (domain_rec["status"] == "active"
                and not invariants.has_active_backing(domain_rec)):
            domain_rec["status"] = "pending"

    since_aw = None if full else st["checkpoints"][config.AWAVENUE]
    aw_issues = client.all_issues(config.AWAVENUE, since=since_aw)
    confirmed = awavenue.scan_issues(client, aw_issues, st, awavenue_main, full=full)
    for d, rec in confirmed.items():
        existed = d in st["domains"]
        state.merge_records(st, {d: rec})
        if not existed and st["domains"][d]["status"] == "active":
            run_info["new_domains"].append(d)

    # ---- 3. promote pending, consolidate referrals, apply overrides ---------
    for d in awavenue.promote_pending(st, awavenue_main):
        if st["domains"][d]["status"] == "active" and d not in run_info["promoted"]:
            run_info["promoted"].append(d)
    # referral merge sits between promotion and overrides: promoted records
    # gain provenance, and an approve/deny always lands on the merged state
    # (a deny after the merge still wins — any status -> rejected)
    added, suppressed, ref_demoted = _merge_referral(st, cats_text, anudeep_text,
                                                     adg_exc, traced_exceptions,
                                                     run_info["date"])
    run_info["referral_added"] = added
    if suppressed:
        run_info["referral_suppressed"] = suppressed
    if ref_demoted:
        run_info["referral_demoted"] = ref_demoted
    run_info["approved"] = state.apply_overrides(st)
    rej_fixed = _reapply_rejection_seeds(st)
    if rej_fixed:
        run_info["rejection_fixed"] = rej_fixed

    # ---- 4. charter invariants + cross status -------------------------------
    conflicts, recovered = invariants.enforce_invariants(
        st, awavenue_main, antiad_block, adguard_block, adguard_allow)
    run_info["conflicts"] = conflicts
    run_info["recovered"] = recovered
    invariants.refresh_cross_status(st, awavenue_main, antiad_block, adguard_block)
    stance = _referral_stance_conflicts(st, antiad_block, awavenue_main)
    if stance:
        run_info["referral_stance_conflicts"] = stance

    # ---- 5. checkpoint, persist, render -------------------------------------
    st["checkpoints"] = {config.ANTIAD: run_start, config.AWAVENUE: run_start}
    state.save(st)
    doms = render.render_lists(st, config.OUTPUT_DIR)
    render.render_provenance(st, config.OUTPUT_DIR)
    render.render_noref_reference(st, config.OUTPUT_DIR)
    render.render_annotated_list(st, config.OUTPUT_DIR)
    after = _snapshot(st)
    run_info["substantive_changed"] = _substantive(before, after)
    flag = os.path.join(config.OUTPUT_DIR, "changed.flag")
    if run_info["substantive_changed"]:
        with open(flag, "w", encoding="utf-8") as f:
            f.write(now_iso() + "\n")
    elif os.path.exists(flag):
        os.remove(flag)
    run_info["api_calls"] = client.calls
    render.render_report(st, config.OUTPUT_DIR, run_info)
    log.info("run done: %d active | new=%d promoted=%d approved=%d conflicts=%d "
             "recovered=%d | substantive=%s | api calls=%d",
             len(doms), len(run_info["new_domains"]),
             len(run_info["promoted"]), len(run_info.get("approved", [])),
             len(run_info["conflicts"]), len(run_info.get("recovered", [])),
             run_info["substantive_changed"], client.calls)
