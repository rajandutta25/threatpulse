"""REST API + dashboard."""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from . import detections, exporters, pipeline
from .collectors import HTTP
from .config import Config, load_config
from .db import DB
from .ioc import classify, ioc_id, refang

STATIC = Path(__file__).parent / "static"


def create_app(cfg: Config | None = None, db: DB | None = None, http=None) -> FastAPI:
    cfg = cfg or load_config()
    db = db or DB(cfg.db_path)
    lock = threading.Lock()
    state = {"running": False, "last": None, "summary": None}
    app = FastAPI(title="ThreatPulse", version="1.0",
                  description="Open-source threat intelligence: advisories, IOCs, actions and detections.")

    def _http():
        return http or HTTP(cfg)

    def refresh_job():
        if not lock.acquire(blocking=False):
            return
        state["running"] = True
        try:
            state["summary"] = pipeline.run(cfg, db, _http())
            state["last"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        finally:
            state["running"] = False
            lock.release()

    minutes = int(os.environ.get("TP_REFRESH_MINUTES", "0"))
    if minutes > 0:
        def loop():
            while True:
                refresh_job()
                time.sleep(minutes * 60)
        threading.Thread(target=loop, daemon=True).start()

    def advisory_inds(aid: str) -> list[dict]:
        return db.q("SELECT i.* FROM indicators i JOIN advisory_indicators l ON l.indicator_id=i.id "
                    "WHERE l.advisory_id=? ORDER BY i.score DESC", (aid,))

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/health")
    def health():
        return {"ok": True, **state}

    @app.get("/api/stats")
    def stats():
        c = lambda sql, a=(): db.conn.execute(sql, a).fetchone()[0]  # noqa: E731
        by_type = {r["type"]: r["n"] for r in db.q("SELECT type, COUNT(*) n FROM indicators GROUP BY type")}
        return {
            "advisories": c("SELECT COUNT(*) FROM advisories"),
            "critical": c("SELECT COUNT(*) FROM advisories WHERE score>=75"),
            "relevant": c("SELECT COUNT(*) FROM advisories WHERE relevant=1"),
            "indicators": c("SELECT COUNT(*) FROM indicators"), "indicators_by_type": by_type,
            "kev": c("SELECT COUNT(*) FROM vulns WHERE kev=1"),
            "kev_ransomware": c("SELECT COUNT(*) FROM vulns WHERE kev=1 AND ransomware=1"),
            "top_malware": db.q("SELECT malware, COUNT(*) n FROM indicators WHERE malware IS NOT NULL "
                                "GROUP BY malware ORDER BY n DESC LIMIT 10"),
            "sources": db.q("SELECT source, status, MAX(finished) finished, advisories, indicators, message "
                            "FROM runs GROUP BY source ORDER BY source"),
            "refresh": state,
        }

    @app.get("/api/advisories")
    def advisories(q: str = "", min_score: float = 0, source: str = "", relevant: bool = False,
                   days: int = 30, limit: int = Query(100, le=1000)):
        sql = ("SELECT a.*, (SELECT COUNT(*) FROM advisory_indicators l WHERE l.advisory_id=a.id) ioc_count "
               "FROM advisories a WHERE score>=? AND published>=datetime('now', ?)")
        args: list = [min_score, f"-{days} days"]
        if q:
            sql += " AND (title LIKE ? OR summary LIKE ? OR cves LIKE ? OR malware LIKE ? OR tags LIKE ?)"
            args += [f"%{q}%"] * 5
        if source:
            sql += " AND source LIKE ?"
            args.append(f"%{source}%")
        if relevant:
            sql += " AND relevant=1"
        sql += " ORDER BY score DESC, published DESC LIMIT ?"
        args.append(limit)
        rows = db.q(sql.replace("published>=datetime('now', ?)", "replace(published,'T',' ')>=datetime('now', ?)"),
                    tuple(args))
        return rows

    @app.get("/api/advisories/{aid}")
    def advisory(aid: str):
        a = db.one("SELECT * FROM advisories WHERE id=?", (aid,))
        if not a:
            raise HTTPException(404, "not found")
        a["vulns"] = [v for v in (db.one("SELECT * FROM vulns WHERE cve=?", (c,)) for c in a["cves"]) if v]
        a["indicators"] = advisory_inds(aid)
        a["detections"] = detections.generate(a["indicators"], a["title"], a["severity"])
        return a

    @app.get("/api/advisories/{aid}/stix")
    def advisory_stix(aid: str):
        a = advisory(aid)
        return exporters.stix_bundle(a["indicators"], [a], {aid: [i["id"] for i in a["indicators"]]}, a["vulns"])

    @app.get("/api/indicators")
    def indicators(type: str = "", q: str = "", min_score: float = 0, malware: str = "",
                   limit: int = Query(500, le=50000)):
        sql, args = "SELECT * FROM indicators WHERE score>=?", [min_score]
        if type:
            sql += " AND type=?"
            args.append(type)
        if q:
            sql += " AND value LIKE ?"
            args.append(f"%{q}%")
        if malware:
            sql += " AND malware LIKE ?"
            args.append(f"%{malware}%")
        sql += " ORDER BY score DESC, last_seen DESC LIMIT ?"
        args.append(limit)
        return db.q(sql, tuple(args))

    @app.get("/api/vulns")
    def vulns(kev: bool = False, min_risk: float = 0, limit: int = Query(200, le=5000)):
        sql = "SELECT * FROM vulns WHERE risk>=?" + (" AND kev=1" if kev else "")
        return db.q(sql + " ORDER BY risk DESC, kev_added DESC LIMIT ?", (min_risk, limit))

    @app.get("/api/lookup")
    def lookup(value: str):
        v = refang(value.strip())
        if v.upper().startswith("CVE-"):
            cve = v.upper()
            return {"type": "cve", "value": cve, "vuln": db.one("SELECT * FROM vulns WHERE cve=?", (cve,)),
                    "advisories": db.q("SELECT id,title,source,score,published FROM advisories WHERE cves LIKE ?",
                                       (f'%"{cve}"%',))}
        t = classify(v)
        if not t:
            raise HTTPException(400, "unrecognised indicator")
        ind = db.one("SELECT * FROM indicators WHERE id=?", (ioc_id(t, v),))
        advs = db.q("SELECT a.id,a.title,a.source,a.score,a.published FROM advisories a JOIN advisory_indicators l "
                    "ON l.advisory_id=a.id WHERE l.indicator_id=?", (ioc_id(t, v),)) if ind else []
        return {"type": t, "value": v, "found": bool(ind), "indicator": ind, "advisories": advs}

    @app.post("/api/refresh")
    def refresh():
        if state["running"]:
            return JSONResponse({"status": "already running"}, 409)
        threading.Thread(target=refresh_job, daemon=True).start()
        return {"status": "started"}

    # ---------- exports ----------
    def _export_set(min_score: float, days: int):
        return db.q("SELECT * FROM indicators WHERE score>=? AND replace(last_seen,'T',' ')>=datetime('now', ?) "
                    "ORDER BY score DESC", (min_score, f"-{days} days"))

    @app.get("/api/export/stix")
    def export_stix(min_score: float = 60, days: int = 30):
        inds = _export_set(min_score, days)
        advs = db.q("SELECT * FROM advisories WHERE score>=? ORDER BY score DESC LIMIT 200", (min_score,))
        links = {a["id"]: [r["indicator_id"] for r in db.q(
            "SELECT indicator_id FROM advisory_indicators WHERE advisory_id=?", (a["id"],))] for a in advs}
        cves = {c for a in advs for c in a["cves"]}
        vs = [v for v in (db.one("SELECT * FROM vulns WHERE cve=?", (c,)) for c in cves) if v]
        return exporters.stix_bundle(inds, advs, links, vs)

    @app.get("/api/export/csv", response_class=PlainTextResponse)
    def export_csv(min_score: float = 0, days: int = 30):
        return PlainTextResponse(exporters.to_csv(_export_set(min_score, days)), media_type="text/csv")

    @app.get("/api/export/edl/{ioc_type}", response_class=PlainTextResponse)
    def export_edl(ioc_type: str, min_score: float = 60, days: int = 14):
        if ioc_type not in ("ipv4", "domain", "url", "sha256", "md5", "sha1"):
            raise HTTPException(400, "type must be ipv4|domain|url|sha256|sha1|md5")
        return exporters.to_edl(_export_set(min_score, days), ioc_type)

    @app.get("/api/export/suricata", response_class=PlainTextResponse)
    def export_suricata(min_score: float = 70, days: int = 14):
        return exporters.to_suricata(_export_set(min_score, days))

    app.state.db, app.state.cfg = db, cfg
    return app


def app_factory():  # for `uvicorn threatpulse.api:app_factory --factory`
    return create_app()
