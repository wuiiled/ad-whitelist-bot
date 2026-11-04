"""Minimal rate-limit-aware GitHub REST client (stdlib only)."""
from __future__ import annotations

import http.client
import json
import logging
import os
import time
import urllib.error
import urllib.request

from . import config

log = logging.getLogger(__name__)
API = "https://api.github.com"
_TRANSIENT = (urllib.error.URLError, TimeoutError, ConnectionError,
              http.client.HTTPException, OSError)


class GitHubClient:
    """GET-only client with rate-limit backoff and transient-error retry."""

    def __init__(self, token: str | None = None):
        self.token = token or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not self.token:
            raise SystemExit("GH_TOKEN (or GITHUB_TOKEN) env var is required")
        self.calls = 0

    def get(self, url: str, tries: int = 6, raw: bool = False):
        last: Exception | None = None
        for attempt in range(tries):
            try:
                req = urllib.request.Request(url)
                req.add_header("Authorization", f"Bearer {self.token}")
                req.add_header("Accept", "application/vnd.github+json")
                req.add_header("User-Agent", "ad-whitelist-bot")
                req.add_header("X-GitHub-Api-Version", "2022-11-28")
                with urllib.request.urlopen(req, timeout=30) as resp:
                    self.calls += 1
                    data = resp.read()
                    return data.decode("utf-8") if raw else json.loads(data)
            except urllib.error.HTTPError as exc:
                if exc.code in (403, 429) and exc.headers.get("X-RateLimit-Remaining") == "0":
                    reset = int(exc.headers.get("X-RateLimit-Reset", "0"))
                    wait = min(max(reset - time.time(), 0) + 5, 3600)
                    log.warning("rate limit hit; sleeping %ds", wait)
                    time.sleep(wait)
                    last = exc
                    continue
                if exc.code in (500, 502, 503, 504):
                    last = exc
                    time.sleep(min(60, 5 * (attempt + 1)))
                    continue
                raise  # 404 etc. are real answers
            except _TRANSIENT as exc:  # includes http.client.IncompleteRead
                last = exc
                time.sleep(min(60, 5 * (attempt + 1)))
        raise RuntimeError(f"GET failed after {tries} tries: {url}: {last}") from last

    def get_raw(self, url: str) -> str:
        return self.get(url, raw=True)

    # ------------------------------------------------------------ wrappers
    def all_issues(self, repo: str, since: str | None = None) -> list[dict]:
        """All issues (state=all) with PRs filtered out, newest activity last."""
        out: list[dict] = []
        page = 1
        while True:
            url = f"{API}/repos/{repo}/issues?state=all&per_page={config.PER_PAGE}&page={page}"
            if since:
                url += f"&since={since}"
            batch = self.get(url)
            if not batch:
                break
            out.extend(it for it in batch if "pull_request" not in it)
            if len(batch) < config.PER_PAGE:
                break
            page += 1
        return out

    def comments(self, repo: str, number: int) -> list[dict]:
        out: list[dict] = []
        page = 1
        while True:
            batch = self.get(f"{API}/repos/{repo}/issues/{number}/comments"
                             f"?per_page={config.PER_PAGE}&page={page}")
            if not batch:
                break
            out.extend(batch)
            if len(batch) < config.PER_PAGE:
                break
            page += 1
        return out

    def commits(self, repo: str, sha: str, path: str, since: str) -> list[dict]:
        return self.get(f"{API}/repos/{repo}/commits?sha={sha}"
                        f"&path={path}&since={since}&per_page={config.PER_PAGE}")
