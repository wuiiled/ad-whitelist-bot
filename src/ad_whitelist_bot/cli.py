"""CLI entry point: `ad-whitelist-bot seed|run` (also `python -m ad_whitelist_bot`)."""
from __future__ import annotations

import argparse
import logging
import sys


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="ad-whitelist-bot",
        description="Collect maintainer-confirmed false-positive domains from "
                    "anti-AD / AWAvenue-Ads-Rule GitHub issues.")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed", help="build data/state.json from live whitelist php + human-audit seeds")
    run_p = sub.add_parser("run", help="daily update (incremental by default)")
    run_p.add_argument("--full", action="store_true",
                       help="scan all issues, not just those updated since the last checkpoint")
    args = ap.parse_args(argv)

    _setup_logging(args.verbose)

    from . import pipeline  # after logging setup so module logs are configured

    if args.cmd == "seed":
        pipeline.seed()
    else:
        pipeline.run(full=args.full)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
