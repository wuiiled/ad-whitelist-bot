"""Curated referral sources: third-party allowlist files the consumer stack
previously downloaded raw (Cats-Team/AdRules dns-allowlist, anudeepND/whitelist,
and the un-annotated remainder of the AdGuardSDNSFilter exceptions file).

Charter position: these feeds carry no false-positive adjudication of their
own — they are curated "better safe than sorry" lists. The bot imports them
(kind="referral", file provenance) so the whitelist product has ONE synthesis
point, with three safety rails:
- referral sources never tighten other sources' invariant keys (a php-backed
  domain stays php-keyed even if Cats also allows it) — see
  invariants._checked_keys;
- referral sources never promote or create records in the human review queue
  or the rejection layer (state.merge_referral skips pending/rejected);
- bare (two-label) referral entries stay in the SUFFIX-tier main file — their
  curation intent is infrastructure allows (cloudfront.net, amazonaws.com,
  akamaized.net, ...), while bare entries from adjudicating sources go to the
  exact-tier file (see render.render_lists).
"""
from __future__ import annotations

import logging
import re

from .. import config, extract
from . import adguardsdns

log = logging.getLogger(__name__)

# `#123` style Cats issue references (full URLs are handled by the shared
# ISSUE_URL_RE in adguardsdns; Cats comments only ever use bare `#N`).
CATS_ISSUE_REF_RE = re.compile(r"(?<![#&\w])#(\d{2,5})\b")

# Reject IP literals early in the line parser (mirrors consumer semantics).
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$")


def parse_domain_line(line: str) -> str | None:
    """Strict bare-domain parser for curated file lines.

    Accepts exactly what the consumer's normalizer accepts for these feeds
    (plain `a.b.c` domains, leading-digit labels, punycode or plain-ASCII);
    rejects comments, section markers, regex lines (`is[0-9]-ssl...`),
    wildcards, paths, ports, IPs, and single labels. Non-ASCII input is
    rejected — none of the three feeds ships IDN names (verified 2026-11-16).
    """
    s = line.strip().lower()
    if not s or len(s) > 100:
        return None
    s = s.split("#", 1)[0].split(";", 1)[0].strip()
    if not s or s.startswith(("/", "*")) or " " in s or ":" in s \
            or "/" in s or "*" in s or "\\" in s or "[" in s:
        return None
    if _IPV4_RE.match(s):
        return None
    labels = s.split(".")
    if len(labels) < 2 or any(not lbl or not _LABEL_RE.match(lbl)
                              for lbl in labels):
        return None
    return s


def _cats_refs(line: str) -> list[dict]:
    return [{"n": int(n), "repo": config.CATS}
            for n in CATS_ISSUE_REF_RE.findall(line)]


def iter_annotated_domains(text: str):
    """Cats-style block binding: `#`/`!` comment lines carry issue refs that
    bind to the following run of domain lines. Blank lines and `#!` section
    markers clear the block — and so does any comment line once a domain was
    consumed: a comment labels exactly the run after it (2026-11-16 real-file
    measurement: inheriting refs across ref-less comments mis-attributes 62
    domains, e.g. `#百度地图 #201` → newvector.map.baidu.com → `#额外` →
    sv.map.baidu.com). Yields (domain, issues)."""
    refs: list[dict] = []
    seen_dom = False
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#!"):  # blank / section marker: clear block
            refs = []
            seen_dom = False
            continue
        if s.startswith("#") or s.startswith("!"):
            if seen_dom:
                refs = []
                seen_dom = False
            new_refs = _cats_refs(s)
            if new_refs:
                refs = new_refs
            continue
        dom = parse_domain_line(s)
        if dom:
            seen_dom = True
            yield dom, refs


def harvest_cats(text: str) -> dict[str, dict]:
    records: dict[str, dict] = {}
    for dom, refs in iter_annotated_domains(text):
        src = {"repo": config.CATS, "kind": "referral",
               "action": "curated allowlist entry"}
        if refs:
            src["issues"] = refs
        rec = records.setdefault(dom, {"domain": dom, "sources": []})
        if src not in rec["sources"]:
            rec["sources"].append(src)
    return records


def harvest_anudeep(text: str) -> dict[str, dict]:
    records: dict[str, dict] = {}
    for raw in text.splitlines():
        dom = parse_domain_line(raw)
        if not dom:
            continue
        src = {"repo": config.ANUDEEP, "kind": "referral",
               "action": "curated allowlist entry"}
        rec = records.setdefault(dom, {"domain": dom, "sources": []})
        if src not in rec["sources"]:
            rec["sources"].append(src)
    return records


def harvest_exceptions_noref(text: str, traced: set[str]) -> dict[str, dict]:
    """AdGuardSDNSFilter exceptions without any issue annotation.

    The annotated exceptions are harvested by the adguardsdns source as
    traced entries; this takes ONLY the remainder, so together the two
    cover exactly what the consumer's own normalizer extracts from the
    file. `traced` = domains already harvested with annotations.
    """
    records: dict[str, dict] = {}
    for dom, issues, _note in adguardsdns.annotated_rules(
            text, extract.parse_allow_rule_domain_line):
        if issues or dom in traced:
            continue
        src = {"repo": config.ADG_DNS, "kind": "referral",
               "action": "exceptions entry without issue annotation"}
        rec = records.setdefault(dom, {"domain": dom, "sources": []})
        if src not in rec["sources"]:
            rec["sources"].append(src)
    return records


def merge_harvested_records(harvests: list[dict[str, dict]]) -> dict[str, dict]:
    """Merge per-feed {domain -> record} maps into one {domain -> record} map."""
    records: dict[str, dict] = {}
    for harvest in harvests:
        for d, r in harvest.items():
            tgt = records.setdefault(d, {"domain": d, "sources": []})
            for s in r["sources"]:
                if s not in tgt["sources"]:
                    tgt["sources"].append(s)
    log.info("referral harvest: %d domains", len(records))
    return records


def build_records(cats_text: str, anudeep_text: str,
                  exceptions_text: str, traced_exceptions: set[str],
                  ) -> dict[str, dict]:
    """Merge the three referral feeds into one {domain -> record} map."""
    return merge_harvested_records([
        harvest_cats(cats_text),
        harvest_anudeep(anudeep_text),
        harvest_exceptions_noref(exceptions_text, traced_exceptions),
    ])
