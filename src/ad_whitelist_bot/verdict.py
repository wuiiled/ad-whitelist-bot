"""Verdict engine: classify maintainer comments into confirmed / rejected / pending."""
from __future__ import annotations

import re

from . import config

ACCEPT = re.compile(config.ACCEPT_RE)
REJECT = re.compile(config.REJECT_RE)
SELF_SERVICE = re.compile(config.SELF_SERVICE_RE)
WHITELIST_VERB = re.compile(config.WHITELIST_VERB_RE)
ALREADY_DONE = re.compile(config.ALREADY_DONE_RE)
PENDING_MARK = re.compile(config.PENDING_MARK_RE)


def is_maintainer(author: str, association: str | None, repo: str) -> bool:
    """A maintainer is anyone with an authoritative association on the repo,
    or a login on the explicit fallback list."""
    if association in config.MAINT_ASSOCIATIONS:
        return True
    return author in config.MAINTAINERS.get(repo, set())


def classify_comment(body: str | None) -> str | None:
    """Classify one comment: 'accept' | 'reject' | 'self_service' | None.

    When both signals appear, the LAST matching sentence wins — the final
    call usually comes last in a maintainer's reply.
    """
    text = body or ""
    if (SELF_SERVICE.search(text) and WHITELIST_VERB.search(text)
            and not ALREADY_DONE.search(text)):
        return "self_service"
    has_accept = ACCEPT.search(text)
    has_reject = REJECT.search(text)
    if has_accept and has_reject:
        return _classify_tail(text)
    if has_accept:
        return "accept"
    if has_reject:
        return "reject"
    return None


def _classify_tail(text: str) -> str | None:
    sentences = [s for s in re.split(r"[。！!?\n]", text) if s.strip()]
    for sentence in reversed(sentences):
        if ACCEPT.search(sentence):
            return "accept"
        if REJECT.search(sentence):
            return "reject"
    return None


def verdict_from_comments(comments: list[dict], repo: str) -> tuple[str | None, str | None, str]:
    """Fold chronological comments into a verdict.

    Returns (verdict, evidence_phrase, verdict_comment_body) where verdict is
    one of 'confirmed' | 'confirmed_pending' | 'rejected' | 'self_service'
    | None. The LAST maintainer comment carrying a signal decides; its body
    is returned so callers can attribute domains to the confirming comment.
    """
    verdict: str | None = None
    evidence: str | None = None
    verdict_body = ""
    maint_bodies: list[str] = []
    for c in comments:
        if not is_maintainer(c.get("user", ""), c.get("author_association"), repo):
            continue  # audit fix: only maintainer comments may set a verdict
        maint_bodies.append(c.get("body") or "")
        cls = classify_comment(c.get("body"))
        if cls is None:
            continue
        if cls == "accept":
            verdict = "confirmed"
            evidence = _first_match(ACCEPT, c.get("body"))
            verdict_body = c.get("body") or ""
        elif cls == "reject":
            verdict = "rejected"
            evidence = _first_match(REJECT, c.get("body"))
            verdict_body = c.get("body") or ""
        elif cls == "self_service" and verdict is None:
            verdict = "self_service"
            evidence = "self-service advice"
            verdict_body = c.get("body") or ""
    if verdict == "confirmed" and PENDING_MARK.search(" ".join(maint_bodies)):
        verdict = "confirmed_pending"
    return verdict, evidence, verdict_body


def _first_match(regex: re.Pattern, text: str | None) -> str | None:
    m = regex.search(text or "")
    return m.group(0) if m else None
