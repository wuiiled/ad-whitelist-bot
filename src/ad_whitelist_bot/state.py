"""Persistent state: domain records, per-issue records, checkpoints.

The state is a single JSON document (data/state.json) committed back to the
repository by CI — it is the bot's memory between daily runs. Shapes are
described with TypedDicts; the JSON on disk is the source of truth.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, TypedDict

from . import config, extract

log = logging.getLogger(__name__)

STATE_VERSION = 1


class IssueRef(TypedDict):
    n: int
    repo: str


class SourceRecord(TypedDict, total=False):
    repo: str
    kind: str  # whitelist-php | issue-only | issue-confirmed | manual | rejected
    value: int  # anti-AD php whitelist semantics (0/1)
    comment: str
    issues: list[IssueRef]
    action: str
    note: str
    audited: bool  # set on human-audited seeds; never overwritten by scans
    attributed_by: str  # "commit-message" when attribution came from commits
    php_removed: str  # date the entry disappeared from the live whitelist php


class ReversalInfo(TypedDict):
    where: str
    detected: str


class DomainRecord(TypedDict, total=False):
    domain: str
    sources: list[SourceRecord]
    status: str  # active | pending | rejected | conflict
    approved_by: str
    conflict: ReversalInfo
    partial_block: str  # informational: ancestor blocked in anti-ad-domains.txt
    in_awavenue_main_now: bool
    in_antiad_block_now: bool


class IssueRecord(TypedDict, total=False):
    status: str  # done | rejected | pending | no-verdict
    locked: bool  # human-audited; scans never overwrite
    title: str
    verdict: str | None
    evidence: str | None
    domains: list[str]
    comments_count: int
    updated_at: str
    issue_state: str


class State(TypedDict, total=False):
    version: int
    generated_at: str
    checkpoints: dict[str, str | None]
    domains: dict[str, DomainRecord]
    issues: dict[str, dict[str, IssueRecord]]
    whitelist_php_snapshot: dict[str, int]
    whitelist_php_noref: dict[str, str]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime(config.GITHUB_TS_FMT)


def empty_state() -> State:
    return {
        "version": STATE_VERSION,
        "generated_at": now_iso(),
        "checkpoints": {repo: None for repo in config.ALL_REPOS},
        "domains": {},
        "issues": {repo: {} for repo in config.ALL_REPOS},
        "whitelist_php_snapshot": {},
        "whitelist_php_noref": {},
    }


def load(path: str = config.STATE_PATH) -> State:
    if not os.path.exists(path):
        log.warning("state file missing at %s, starting empty", path)
        return empty_state()
    with open(path, encoding="utf-8") as f:
        st = json.load(f)
    for repo in config.ALL_REPOS:  # normalize shape across version changes
        st.setdefault("issues", {}).setdefault(repo, {})
    st.setdefault("domains", {})
    st.setdefault("checkpoints", {repo: None for repo in config.ALL_REPOS})
    st.setdefault("whitelist_php_snapshot", {})
    st.setdefault("whitelist_php_noref", {})
    return st


def save(st: State, path: str = config.STATE_PATH) -> None:
    st["generated_at"] = now_iso()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(st, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, path)  # atomic: CI commit never sees a half-written file


# ------------------------------------------------------------- merging ----

def merge_domain(st: State, domain: str, source: SourceRecord | None = None) -> DomainRecord:
    """Get-or-create a domain record, optionally appending one source.

    `pending` flips back to `active` when new evidence arrives, EXCEPT for
    domains a human explicitly approved — manual decisions are never demoted.
    """
    rec: DomainRecord = st["domains"].setdefault(
        domain, {"domain": domain, "sources": [], "status": "active"})
    if source is not None and source not in rec["sources"]:
        rec["sources"].append(source)
    if rec["status"] == "pending" and not rec.get("approved_by"):
        rec["status"] = "active"
    return rec


def merge_records(st: State, records: dict[str, dict]) -> list[str]:
    """Merge {domain -> {sources: [...]}} records; returns newly added domains."""
    new: list[str] = []
    for d, rec in records.items():
        existed = d in st["domains"]
        domain_rec = merge_domain(st, d)
        for src in rec["sources"]:
            if src not in domain_rec["sources"]:
                domain_rec["sources"].append(src)
        if not existed:
            new.append(d)
    return new


def load_seed_json(name: str) -> Any | None:
    path = os.path.join(config.DATA_DIR, name)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def apply_overrides(st: State) -> list[str]:
    """Apply data/manual_overrides.json — the human review layer.

    approve entries may be plain domain strings, or dicts carrying issue
    provenance for decisions that predate the automation:
        {"domain": "x.com", "issues": [{"n": 123, "repo": "owner/repo"}],
         "note": "why"}
    approve: pending -> active (creates the record if it does not exist yet).
    deny:    any status -> rejected (sticky; scans never re-activate).
    Returns the list of newly approved domains.
    """
    ov = load_seed_json("manual_overrides.json") or {}
    approved: list[str] = []
    for entry in ov.get("approve", []):
        if isinstance(entry, str):
            domain, issues, note = entry, [], ""
        else:
            domain = entry["domain"]
            issues = entry.get("issues", [])
            note = entry.get("note", "")
        rec = st["domains"].get(domain)
        if rec is None:
            merge_domain(st, domain, {
                "repo": "manual", "kind": "manual",
                "action": note or "human-approved via manual_overrides.json",
                "issues": issues})
            rec = st["domains"][domain]
            rec["approved_by"] = "manual_overrides"
            approved.append(domain)
        else:
            if rec["status"] == "pending":
                rec["status"] = "active"
                rec["approved_by"] = "manual_overrides"
                approved.append(domain)
            # human-provided issue provenance subsumes older issue-less manual
            # sources; prune them idempotently, then add provenance if missing
            if issues:
                rec["sources"] = [s for s in rec["sources"]
                                  if not (s.get("kind") == "manual"
                                          and not s.get("issues"))]
                if not any(s.get("issues") for s in rec["sources"]):
                    rec["sources"].append({
                        "repo": "manual", "kind": "manual",
                        "action": note or "human-approved via manual_overrides.json",
                        "issues": issues})
    for d in ov.get("deny", []):
        rec = st["domains"].get(d)
        if rec:
            rec["status"] = "rejected"
    return approved
