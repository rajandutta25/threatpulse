"""Orchestration: collect -> normalize/store -> enrich -> correlate -> score -> act -> notify."""
from __future__ import annotations

import json
import logging
import re

from .collectors import FEED_COLLECTORS, Batch, Epss, Nvd
from .config import Config
from .db import DB, now
from .playbook import build_actions
from .scoring import advisory_score, indicator_score, is_relevant, vuln_risk

log = logging.getLogger("threatpulse")


def store(db: DB, batch: Batch) -> tuple[int, int, list[str]]:
    new_ids, n_ind = [], 0
    for v in batch.vulns:
        db.upsert_vuln(v)
    for adv in batch.advisories:
        inds = adv.pop("indicators", [])
        if db.upsert_advisory(adv):
            new_ids.append(adv["id"])
        for i in inds:
            db.link(adv["id"], db.upsert_indicator(i))
            n_ind += 1
    for i in batch.indicators:
        db.upsert_indicator(i)
        n_ind += 1
    db.commit()
    return len(batch.advisories), n_ind, new_ids


def enrich(cfg: Config, db: DB, http) -> None:
    cves = sorted({c for a in db.q("SELECT cves FROM advisories") for c in a["cves"]})
    for c in cves:
        if not db.one("SELECT cve FROM vulns WHERE cve=?", (c,)):
            db.upsert_vuln({"cve": c})
    db.commit()
    missing_cvss = [r["cve"] for r in db.q("SELECT cve FROM vulns WHERE cvss IS NULL AND cve IN "
                                           f"({','.join('?' * len(cves))}) ORDER BY kev DESC", tuple(cves))] if cves else []
    missing_epss = [r["cve"] for r in db.q("SELECT cve FROM vulns WHERE epss IS NULL")]
    for collector in (Nvd(cfg, http, missing_cvss), Epss(cfg, http, missing_epss)):
        started = now()
        try:
            b = collector.collect()
            store(db, b)
            db.log_run(collector.name, started, "ok", 0, 0, f"{len(b.vulns)} vulns enriched")
        except Exception as e:
            db.log_run(collector.name, started, "error", message=str(e)[:500])


def correlate(db: DB, cfg: Config) -> int:
    """Link feed IOCs (ThreatFox/Feodo/URLhaus) to advisories that mention the same malware family."""
    families = {r["malware"] for r in db.q("SELECT DISTINCT malware FROM indicators WHERE malware IS NOT NULL")
                if r["malware"] and len(r["malware"]) >= 4 and r["malware"].lower() not in ("unknown", "none")}
    linked = 0
    for a in db.q("SELECT id,title,summary,malware FROM advisories"):
        text = f"{a['title']} {a['summary']}"
        hits = set(a["malware"]) | {f for f in families if re.search(rf"\b{re.escape(f)}\b", text, re.I)}
        hits &= families | set(a["malware"])
        if not hits:
            continue
        db.conn.execute("UPDATE advisories SET malware=? WHERE id=?", (json.dumps(sorted(hits)), a["id"]))
        for fam in hits:
            for i in db.q("SELECT id FROM indicators WHERE malware=? COLLATE NOCASE ORDER BY last_seen DESC LIMIT 300",
                          (fam,)):
                db.link(a["id"], i["id"])
                linked += 1
    db.commit()
    return linked


def rescore(db: DB, cfg: Config) -> None:
    for v in db.q("SELECT * FROM vulns"):
        db.conn.execute("UPDATE vulns SET risk=? WHERE cve=?", (vuln_risk(v), v["cve"]))
    for i in db.q("SELECT * FROM indicators"):
        db.conn.execute("UPDATE indicators SET score=? WHERE id=?", (indicator_score(i), i["id"]))
    for a in db.q("SELECT * FROM advisories"):
        vulns = [db.one("SELECT * FROM vulns WHERE cve=?", (c,)) for c in a["cves"]]
        vulns = [v for v in vulns if v]
        inds = db.q("SELECT i.* FROM indicators i JOIN advisory_indicators l ON l.indicator_id=i.id "
                    "WHERE l.advisory_id=?", (a["id"],))
        rel = is_relevant(f"{a['title']} {a['summary']}", cfg.watch_vendors, cfg.watch_products, vulns)
        score = advisory_score(a, vulns, len(inds), rel)
        actions = build_actions(a, vulns, inds, rel)
        db.conn.execute("UPDATE advisories SET score=?, relevant=?, actions=? WHERE id=?",
                        (score, int(rel), json.dumps(actions), a["id"]))
    db.commit()


def notify(cfg: Config, db: DB, http) -> int:
    if not cfg.webhook_url:
        return 0
    sent = 0
    for a in db.q("SELECT * FROM advisories WHERE notified=0 AND score>=? ORDER BY score DESC LIMIT 20",
                  (cfg.notify_min_score,)):
        p1 = [x["action"] for x in a["actions"] if x["priority"] == "P1"][:3]
        text = (f"*[ThreatPulse {a['score']:.0f}]* {'🎯 YOUR STACK — ' if a['relevant'] else ''}{a['title']}\n"
                f"{a['source']} · {a['url']}\n" + "\n".join(f"• {x}" for x in p1))
        try:
            http.post_json(cfg.webhook_url, {"text": text})  # Slack & Teams (incoming webhook) accept {"text"}
            db.conn.execute("UPDATE advisories SET notified=1 WHERE id=?", (a["id"],))
            sent += 1
        except Exception as e:
            log.warning("webhook failed: %s", e)
    db.commit()
    return sent


def prune(db: DB, keep_days: int = 90) -> int:
    """Drop advisories and indicators not seen for keep_days so long-running instances stay small."""
    cut = f"-{keep_days} days"
    n = db.conn.execute("DELETE FROM advisories WHERE replace(published,'T',' ') < datetime('now', ?)", (cut,)).rowcount
    n += db.conn.execute("DELETE FROM indicators WHERE replace(last_seen,'T',' ') < datetime('now', ?)", (cut,)).rowcount
    db.conn.execute("DELETE FROM advisory_indicators WHERE advisory_id NOT IN (SELECT id FROM advisories) "
                    "OR indicator_id NOT IN (SELECT id FROM indicators)")
    db.conn.execute("DELETE FROM runs WHERE replace(finished,'T',' ') < datetime('now', '-14 days')")
    db.commit()
    return n


def run(cfg: Config, db: DB, http, only: list[str] | None = None) -> dict:
    summary = {}
    for cls in FEED_COLLECTORS:
        if only and cls.name not in only:
            continue
        c = cls(cfg, http)
        ok, why = c.available()
        if not cfg.source_enabled(c.name) or not ok:
            summary[c.name] = f"skipped ({why or 'disabled'})"
            continue
        started = now()
        try:
            n_adv, n_ind, _ = store(db, c.collect())
            db.log_run(c.name, started, "ok", n_adv, n_ind)
            summary[c.name] = f"ok: {n_adv} advisories, {n_ind} indicators"
        except Exception as e:
            db.log_run(c.name, started, "error", message=str(e)[:500])
            summary[c.name] = f"error: {e}"
            log.exception("collector %s failed", c.name)
    summary["pruned"] = prune(db, cfg.retention_days)
    enrich(cfg, db, http)
    summary["correlated_links"] = correlate(db, cfg)
    rescore(db, cfg)
    summary["notifications"] = notify(cfg, db, http)
    return summary
