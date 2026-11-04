"""Domain extraction from free text, with junk filtering."""
from __future__ import annotations

import re

DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?\.)+[a-z]{2,24}", re.I)

# Suffixes that are really filenames in issue text, not domains.
FILE_EXT = frozenset({
    "html", "htm", "css", "js", "json", "xml", "png", "jpg", "jpeg",
    "gif", "webp", "svg", "bmp", "ico", "pdf", "zip", "apk", "mp4",
    "txt", "yaml", "yml", "md", "woff", "woff2", "ttf", "eot", "map",
    "log", "bak", "sql", "csv", "py", "php", "jsp", "so", "dll", "exe",
    "conf", "list", "srs", "mrs", "jar", "rsc", "dat", "module",
    "sgmodule", "plist", "ruleset", "domain",
})

EXACT_JUNK = frozenset({
    "github.com", "github.io", "raw.githubusercontent.com",
    "user-images.githubusercontent.com", "avatars.githubusercontent.com",
    "api.github.com", "img.shields.io", "t.me", "anti-ad.net",
    "awavenue.top", "docs.github.com", "help.github.com",
})

# TLD allowlist for issue-text extraction — kills regex artifacts like
# `1.microsoft`, `thread.message`, `xx.yy`. (Harvested whitelist entries
# bypass this check; only free-text extraction is filtered.)
TLD_ALLOW = frozenset({
    "com", "net", "org", "gov", "edu", "int", "mil", "arpa",
    "cn", "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "hk", "tw", "mo", "jp", "kr", "sg", "my", "th", "vn", "ph", "id", "in",
    "io", "me", "co", "tv", "cc", "xyz", "top", "site", "online", "club",
    "shop", "app", "dev", "live", "news", "info", "biz", "name", "pro",
    "asia", "mobi", "red", "fun", "vip", "wang", "win", "icu", "store",
    "tech", "cloud", "space", "website", "press", "ink", "ltd", "group",
    "pub", "link", "work", "life", "zone", "team", "tools", "cyou", "art",
    "la", "gg", "ai", "sh", "so", "fm", "am", "im", "st", "ly", "to", "gl",
    "gs", "ms", "tc", "je", "gi", "vu", "eu", "ru", "uk", "de", "fr", "us",
    "ca", "au", "nz", "br", "it", "es", "nl", "se", "ch", "no", "dk", "fi",
    "pl", "cz", "at", "be", "pt", "gr", "ie", "il", "tr", "mx", "ar", "cl",
    "za", "ua", "ro", "hu", "bg", "sk", "si", "hr", "rs", "lt", "lv", "ee",
})


def clean_domain(token: str) -> str | None:
    """Normalize one candidate token; return None if it is not a plausible domain."""
    d = token.lower().strip(".").strip()
    if not d or len(d) > 100 or " " in d:
        return None
    if d in EXACT_JUNK:
        return None
    labels = d.split(".")
    if len(labels) < 2 or any(not lbl for lbl in labels):
        return None
    tld = labels[-1]
    if tld.isdigit():  # IP address
        return None
    if tld in FILE_EXT:
        return None
    second_level_tld = ".".join(labels[-2:])
    if tld not in TLD_ALLOW and second_level_tld not in TLD_ALLOW:
        return None
    if "screenshot" in d:
        return None
    return d


def extract_domains(text: str | None) -> list[str]:
    """Ordered, de-duplicated domain list from free text."""
    out: list[str] = []
    for match in DOMAIN_RE.findall(text or ""):
        d = clean_domain(match)
        if d and d not in out:
            out.append(d)
    return out


def suffix_blocked(domain: str, blockset: set[str] | frozenset[str]) -> bool:
    """True if the domain itself or any ancestor is in the block set."""
    labels = domain.split(".")
    return any(".".join(labels[i:]) in blockset for i in range(len(labels)))


def parse_rule_domain_line(line: str) -> str | None:
    """Extract the domain from an AdGuard-style `||domain^` line, else None."""
    s = line.strip()
    if s.startswith("||") and "^" in s:
        return s[2:s.index("^")].lower() or None
    return None


def parse_domain_blocklist(text: str) -> set[str]:
    """Parse a plain hosts/domains blocklist (one domain per line, # comments)."""
    return {ln.strip().lower() for ln in text.splitlines()
            if ln.strip() and not ln.startswith("#")}


def parse_adguard_rule_domainset(text: str) -> set[str]:
    """Parse `||domain^` style rule text into a plain domain set."""
    out = set()
    for ln in text.splitlines():
        d = parse_rule_domain_line(ln)
        if d:
            out.add(d)
    return out
