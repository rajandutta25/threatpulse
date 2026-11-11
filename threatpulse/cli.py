"""Command line: `python -m threatpulse <command>`."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import exporters, pipeline
from .config import load_config
from .db import DB


def main(argv=None):
    p = argparse.ArgumentParser(prog="threatpulse", description="Open-source threat intelligence platform")
    p.add_argument("-c", "--config", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("collect", help="run collectors, enrichment, scoring")
    r.add_argument("--only", nargs="*", help="collector names, e.g. cisa_kev rss otx")
    s = sub.add_parser("serve", help="run API + dashboard")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8080)
    b = sub.add_parser("build-site", help="build a static website (GitHub Pages) from the database")
    b.add_argument("-o", "--output", default="site")
    b.add_argument("--days", type=int, default=30)
    b.add_argument("--feed-min-score", type=float, default=60)
    b.add_argument("--repo-url", default="")
    sub.add_parser("demo", help="load offline sample data (clearly labelled SAMPLE) for a quick tour")
    t = sub.add_parser("top", help="print top advisories with actions")
    t.add_argument("-n", type=int, default=10)
    e = sub.add_parser("export", help="export indicators")
    e.add_argument("format", choices=["stix", "csv", "suricata", "edl-ipv4", "edl-domain", "edl-url"])
    e.add_argument("--min-score", type=float, default=60)
    e.add_argument("-o", "--output", default="-")
    a = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(a.config)

    if a.cmd == "serve":
        import uvicorn
        from .api import create_app
        uvicorn.run(create_app(cfg), host=a.host, port=a.port)
        return

    db = DB(cfg.db_path)
    if a.cmd == "collect":
        from .collectors import HTTP
        print(json.dumps(pipeline.run(cfg, db, HTTP(cfg), a.only), indent=2))
    elif a.cmd == "demo":
        from .fixtures import FixtureHTTP
        cfg.rss_feeds = [{"name": "SAMPLE Vendor Blog", "url": "fixture://rss", "full_text": False}]
        cfg.permit_test_ranges = True
        cfg.otx_key = cfg.otx_key or "demo"
        cfg.abusech_key = cfg.abusech_key or "demo"
        if not cfg.watch_vendors:
            cfg.watch_vendors = ["fortinet", "cisco", "microsoft", "f5", "palo alto"]
        print(json.dumps(pipeline.run(cfg, db, FixtureHTTP()), indent=2))
        print("\nSample data loaded. Run: python -m threatpulse serve")
    elif a.cmd == "build-site":
        from .sitegen import build
        print(json.dumps(build(db, a.output, a.days, feed_min_score=a.feed_min_score, repo_url=a.repo_url), indent=2))
    elif a.cmd == "top":
        for adv in db.q("SELECT * FROM advisories ORDER BY score DESC LIMIT ?", (a.n,)):
            flag = " [YOUR STACK]" if adv["relevant"] else ""
            print(f"\n[{adv['score']:5.1f}]{flag} {adv['title']}\n        {adv['source']} | {adv['url']}")
            for act in adv["actions"][:5]:
                print(f"   {act['priority']} {act['category']:<9} {act['action']}  (due {act['due'] or '-'})")
    elif a.cmd == "export":
        inds = db.q("SELECT * FROM indicators WHERE score>=? ORDER BY score DESC", (a.min_score,))
        if a.format == "stix":
            out = exporters.dumps(exporters.stix_bundle(inds))
        elif a.format == "csv":
            out = exporters.to_csv(inds)
        elif a.format == "suricata":
            out = exporters.to_suricata(inds)
        else:
            out = exporters.to_edl(inds, a.format.split("-")[1])
        if a.output == "-":
            sys.stdout.write(out)
        else:
            Path(a.output).write_text(out)
            print(f"wrote {a.output}")


if __name__ == "__main__":
    main()
