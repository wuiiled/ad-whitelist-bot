"""Shared issue-scanning skeleton used by both project sources.

Handles the mechanics that are identical for every repo — locked records,
comment-count caching, candidate gating, comment fetching, verdict folding —
and hands fully-evaluated issues to the repo-specific scanner.
"""
from __future__ import annotations

import logging
from typing import Callable

from .. import config
from ..state import State

log = logging.getLogger(__name__)

IssueEval = dict  # {"issue", "comments", "verdict", "evidence", "verdict_body", "comments_count"}


def evaluate_issues(
    client,
    repo: str,
    issues: list[dict],
    st: State,
    candidate_fn: Callable[[dict], bool],
    full: bool,
) -> list[IssueEval]:
    """Gate and evaluate candidate issues; returns evaluated (non-skipped) ones.

    - `locked` records are human-audited verdicts: never re-evaluated.
    - done/rejected records are re-evaluated only when new comments appear
      (or on --full scans) — the comment-count cache keeps daily runs cheap.
    - other statuses (pending / no-verdict) are always re-evaluated because
      their outcome may change with new maintainer activity.
    """
    evaluated: list[IssueEval] = []
    for it in issues:
        num = str(it["number"])
        prev = st["issues"][repo].get(num)
        if prev and prev.get("locked"):
            continue
        if not candidate_fn(it):
            continue
        comments_count = it.get("comments", 0)
        if (prev and prev.get("status") in ("done", "rejected")
                and prev.get("comments_count") == comments_count and not full):
            continue
        comments = client.comments(repo, it["number"])
        cs_simple = [{"user": c["user"]["login"],
                      "author_association": c.get("author_association"),
                      "body": c.get("body") or ""} for c in comments]
        v, ev, vbody = _fold(cs_simple, repo)
        evaluated.append({
            "issue": it, "comments": cs_simple, "verdict": v,
            "evidence": ev, "verdict_body": vbody, "comments_count": comments_count,
        })
    return evaluated


def _fold(cs_simple: list[dict], repo: str):
    from .. import verdict  # local import avoids a cycle in type checkers

    return verdict.verdict_from_comments(cs_simple, repo)


def base_issue_record(ev: IssueEval) -> dict:
    it = ev["issue"]
    return {
        "comments_count": ev["comments_count"],
        "updated_at": it["updated_at"],
        "title": (it.get("title") or "")[:120],
        "evidence": ev["evidence"],
        "verdict": ev["verdict"],
    }


STATUS_MAP = {"rejected": "rejected", "self_service": "rejected",
              "confirmed_pending": "pending", None: "no-verdict"}


def record_issue(st: State, repo: str, number: str, rec: dict) -> None:
    st["issues"][repo][number] = rec
