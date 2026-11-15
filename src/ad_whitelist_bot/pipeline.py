"""Pipeline orchestration: `seed` (build initial state) and `run` (daily update)."""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

from . import config, extract, invariants, render, state
from .github import GitHubClient
from .sources import antiad, awavenue
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
    log.info("artifacts: php=%d entries, anti-ad block=%d domains, "
             "awavenue rule=%d domains", len(antiad.parse_white_php(php)),
             len(antiad_block), len(awavenue_main))
    return php, antiad_block, awavenue_main


def seed() -> None:
    """Build data/state.json from the live whitelist php + human-audit seeds."""
    client = GitHubClient()
    st = state.empty_state()
    php, antiad_block, awavenue_main = _fetch_artifacts(client)

    records, noref = antiad.harvest_white_php(php)
    state.merge_records(st, records)
    st["whitelist_php_noref"] = noref
    st["whitelist_php_snapshot"] = {e["domain"]: e["value"]
                                    for e in antiad.parse_white_php(php)
                                    if e["value"] != -1}

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

    from . import invariants
    invariants.enforce_invariants(st, awavenue_main, antiad_block)
    invariants.refresh_cross_status(st, awavenue_main, antiad_block)
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
    records, noref = antiad.harvest_white_php(php)
    snapshot = {e["domain"]: e["value"] for e in antiad.parse_white_php(php)
                if e["value"] != -1}
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

    # ---- 2. issue scans -----------------------------------------------------
    since_aa = None if full else st["checkpoints"][config.ANTIAD]
    aa_issues = client.all_issues(config.ANTIAD, since=since_aa)
    issue_only = antiad.scan_issues(client, aa_issues, st, full=full)
    for d, rec in issue_only.items():
        state.merge_records(st, {d: rec})
        domain_rec = st["domains"][d]
        # anti-AD issue-only confirmations go to the review queue, never
        # straight into the list; human-approved domains are never demoted.
        if (domain_rec["status"] == "active"
                and not any(s["kind"] == "whitelist-php" for s in domain_rec["sources"])):
            domain_rec["status"] = "pending"

    since_aw = None if full else st["checkpoints"][config.AWAVENUE]
    aw_issues = client.all_issues(config.AWAVENUE, since=since_aw)
    confirmed = awavenue.scan_issues(client, aw_issues, st, awavenue_main, full=full)
    for d, rec in confirmed.items():
        existed = d in st["domains"]
        state.merge_records(st, {d: rec})
        if not existed and st["domains"][d]["status"] == "active":
            run_info["new_domains"].append(d)

    # ---- 3. promote pending + apply human overrides -------------------------
    for d in awavenue.promote_pending(st, awavenue_main):
        if st["domains"][d]["status"] == "active" and d not in run_info["promoted"]:
            run_info["promoted"].append(d)
    run_info["approved"] = state.apply_overrides(st)

    # ---- 4. charter invariants + cross status -------------------------------
    conflicts, recovered = invariants.enforce_invariants(st, awavenue_main, antiad_block)
    run_info["conflicts"] = conflicts
    run_info["recovered"] = recovered
    invariants.refresh_cross_status(st, awavenue_main, antiad_block)

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
