"""Pipeline orchestration: `seed` (build initial state) and `run` (daily update)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from . import config, extract, invariants, render, state
from .github import GitHubClient
from .sources import antiad, awavenue
from .state import State, now_iso

log = logging.getLogger(__name__)


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
        for d in removed:  # annotate sources whose php entry disappeared
            rec = st["domains"].get(d)
            if rec:
                for s in rec["sources"]:
                    if s.get("kind") == "whitelist-php":
                        s["php_removed"] = run_info["date"]
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
    run_info["conflicts"] = invariants.enforce_invariants(st, awavenue_main, antiad_block)
    invariants.refresh_cross_status(st, awavenue_main, antiad_block)

    # ---- 5. checkpoint, persist, render -------------------------------------
    st["checkpoints"] = {config.ANTIAD: run_start, config.AWAVENUE: run_start}
    state.save(st)
    doms = render.render_lists(st, config.OUTPUT_DIR)
    render.render_provenance(st, config.OUTPUT_DIR)
    render.render_noref_reference(st, config.OUTPUT_DIR)
    render.render_annotated_list(st, config.OUTPUT_DIR)
    run_info["api_calls"] = client.calls
    render.render_report(st, config.OUTPUT_DIR, run_info)
    log.info("run done: %d active | new=%d promoted=%d approved=%d conflicts=%d "
             "| api calls=%d", len(doms), len(run_info["new_domains"]),
             len(run_info["promoted"]), len(run_info.get("approved", [])),
             len(run_info["conflicts"]), client.calls)
