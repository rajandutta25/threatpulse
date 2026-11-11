"""Builds a static, browsable website (GitHub Pages / any static host) from the database.

Output layout:
  index.html                     dashboard (static mode)
  data/meta.json                 build time, stats, feed health
  data/advisories.json           advisory list (last N days)
  data/advisory/<id>.json        full advisory: CVEs, IOCs, actions, detections
  data/indicators.json           compact IOC index used for browsing + lookup
  data/vulns.json                exploited CVEs ranked by risk
  feeds/*.txt|json|csv|rules     public blocklists / STIX / Suricata / CSV
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from . import detections, exporters
from .db import DB, now

STATIC = Path(__file__).parent / "static"


def _w(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":")))


def build(db: DB, out: str, days: int = 30, max_indicators: int = 50000, feed_min_score: float = 60,
          site_title: str = "ThreatPulse", repo_url: str = "") -> dict:
    o = Path(out)
    if o.exists():
        shutil.rmtree(o)
    (o / "data" / "advisory").mkdir(parents=True)
    since = f"-{days} days"

    advs = db.q("SELECT a.*, (SELECT COUNT(*) FROM advisory_indicators l WHERE l.advisory_id=a.id) ioc_count "
                "FROM advisories a WHERE replace(published,'T',' ')>=datetime('now', ?) "
                "ORDER BY score DESC, published DESC", (since,))
    for a in advs:
        inds = db.q("SELECT i.* FROM indicators i JOIN advisory_indicators l ON l.indicator_id=i.id "
                    "WHERE l.advisory_id=? ORDER BY i.score DESC", (a["id"],))
        vulns = [v for v in (db.one("SELECT * FROM vulns WHERE cve=?", (c,)) for c in a["cves"]) if v]
        full = {**a, "indicators": inds, "vulns": vulns,
                "detections": detections.generate(inds, a["title"], a["severity"])}
        _w(o / "data" / "advisory" / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', a['id'])}.json", full)
    _w(o / "data" / "advisories.json",
       [{k: a[k] for k in ("id", "source", "title", "url", "published", "severity", "score", "cves", "tags",
                           "malware", "ioc_count")} for a in advs])

    inds = db.q("SELECT * FROM indicators WHERE replace(last_seen,'T',' ')>=datetime('now', ?) "
                "ORDER BY score DESC LIMIT ?", (since, max_indicators))
    links: dict[str, list[str]] = {}
    for r in db.q("SELECT advisory_id, indicator_id FROM advisory_indicators"):
        links.setdefault(r["indicator_id"], []).append(r["advisory_id"])
    adv_ids = {a["id"] for a in advs}
    # compact columnar-ish rows keep the file small: [type, value, score, malware, threat, sources, last_seen, ref, advisories]
    _w(o / "data" / "indicators.json",
       [[i["type"], i["value"], round(i["score"]), i["malware"] or "", i["threat_type"] or "", i["sources"],
         (i["last_seen"] or "")[:16], i["reference"] or "", [x for x in links.get(i["id"], []) if x in adv_ids][:5]]
        for i in inds])

    vulns = db.q("SELECT * FROM vulns WHERE kev=1 ORDER BY risk DESC, kev_added DESC LIMIT 1000")
    _w(o / "data" / "vulns.json", vulns)

    feed_set = [i for i in inds if (i["score"] or 0) >= feed_min_score]
    feeds = o / "feeds"
    for t in ("ipv4", "domain", "url", "sha256", "md5"):
        _w(feeds / f"{t}.txt", exporters.to_edl(feed_set, t))
    _w(feeds / "iocs.csv", exporters.to_csv(feed_set))
    _w(feeds / "suricata.rules", exporters.to_suricata(feed_set))
    top_advs = advs[:200]
    adv_links = {a["id"]: [r["indicator_id"] for r in db.q(
        "SELECT indicator_id FROM advisory_indicators WHERE advisory_id=?", (a["id"],))] for a in top_advs}
    cves = {c for a in top_advs for c in a["cves"]}
    _w(feeds / "stix.json", exporters.stix_bundle(
        feed_set, top_advs, adv_links, [v for v in (db.one("SELECT * FROM vulns WHERE cve=?", (c,)) for c in cves) if v]))

    c = lambda sql, a=(): db.conn.execute(sql, a).fetchone()[0]  # noqa: E731
    meta = {
        "built": now(), "title": site_title, "repo": repo_url, "days": days, "feed_min_score": feed_min_score,
        "stats": {"advisories": len(advs), "critical": sum(1 for a in advs if a["score"] >= 75),
                  "indicators": len(inds), "kev": c("SELECT COUNT(*) FROM vulns WHERE kev=1"),
                  "kev_ransomware": c("SELECT COUNT(*) FROM vulns WHERE kev=1 AND ransomware=1"),
                  "feed_iocs": len(feed_set)},
        "top_malware": db.q("SELECT malware, COUNT(*) n FROM indicators WHERE malware IS NOT NULL AND "
                            "replace(last_seen,'T',' ')>=datetime('now', ?) GROUP BY malware ORDER BY n DESC LIMIT 12",
                            (since,)),
        "sources": db.q("SELECT source, status, MAX(finished) finished, advisories, indicators, message "
                        "FROM runs GROUP BY source ORDER BY source"),
    }
    _w(o / "data" / "meta.json", meta)

    html = (STATIC / "index.html").read_text().replace("<!--TP_MODE-->", "<script>window.TP_STATIC=true</script>")
    _w(o / "index.html", html)
    _w(o / ".nojekyll", "")
    return {"advisories": len(advs), "indicators": len(inds), "feed_iocs": len(feed_set), "out": str(o)}
