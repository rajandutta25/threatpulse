"""SQLite storage layer. Zero external dependencies; swap for Postgres later if needed."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY, source TEXT, title TEXT, summary TEXT, url TEXT,
    published TEXT, collected TEXT, severity TEXT, score REAL DEFAULT 0,
    relevant INTEGER DEFAULT 0, cves TEXT DEFAULT '[]', tags TEXT DEFAULT '[]',
    malware TEXT DEFAULT '[]', actions TEXT DEFAULT '[]', notified INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS indicators (
    id TEXT PRIMARY KEY, type TEXT, value TEXT, first_seen TEXT, last_seen TEXT,
    sources TEXT DEFAULT '[]', confidence INTEGER DEFAULT 50, malware TEXT,
    threat_type TEXT, tags TEXT DEFAULT '[]', score REAL DEFAULT 0, reference TEXT
);
CREATE TABLE IF NOT EXISTS advisory_indicators (
    advisory_id TEXT, indicator_id TEXT, PRIMARY KEY (advisory_id, indicator_id)
);
CREATE TABLE IF NOT EXISTS vulns (
    cve TEXT PRIMARY KEY, description TEXT, cvss REAL, cvss_vector TEXT, epss REAL,
    epss_pct REAL, kev INTEGER DEFAULT 0, kev_added TEXT, kev_due TEXT,
    kev_action TEXT, vendor TEXT, product TEXT, ransomware INTEGER DEFAULT 0,
    published TEXT, risk REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT, started TEXT, finished TEXT,
    status TEXT, advisories INTEGER, indicators INTEGER, message TEXT
);
CREATE INDEX IF NOT EXISTS ix_ind_value ON indicators(value);
CREATE INDEX IF NOT EXISTS ix_ind_type ON indicators(type);
CREATE INDEX IF NOT EXISTS ix_adv_pub ON advisories(published);
"""

JSON_COLS = {"cves", "tags", "malware", "actions", "sources"}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DB:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    # ---------- helpers ----------
    @staticmethod
    def row(r: sqlite3.Row | None) -> dict | None:
        if r is None:
            return None
        d = dict(r)
        for k in JSON_COLS & d.keys():
            val = d[k]
            if isinstance(val, str) and val.startswith("["):  # indicators.malware is a plain string
                try:
                    d[k] = json.loads(val)
                except json.JSONDecodeError:
                    pass
            elif val is None and k != "malware":
                d[k] = []
        return d

    def q(self, sql: str, args: tuple = ()) -> list[dict]:
        return [self.row(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql: str, args: tuple = ()) -> dict | None:
        return self.row(self.conn.execute(sql, args).fetchone())

    def commit(self):
        self.conn.commit()

    # ---------- writes ----------
    def upsert_indicator(self, ind: dict) -> str:
        existing = self.one("SELECT * FROM indicators WHERE id=?", (ind["id"],))
        if existing:
            sources = sorted(set(existing["sources"]) | set(ind.get("sources", [])))
            tags = sorted(set(existing["tags"]) | set(ind.get("tags", [])))
            self.conn.execute(
                """UPDATE indicators SET last_seen=?, sources=?, tags=?,
                   confidence=MAX(confidence, ?), malware=COALESCE(malware, ?),
                   threat_type=COALESCE(threat_type, ?), reference=COALESCE(reference, ?) WHERE id=?""",
                (max(existing["last_seen"] or "", ind.get("last_seen") or now()), json.dumps(sources),
                 json.dumps(tags), ind.get("confidence", 50), ind.get("malware"), ind.get("threat_type"),
                 ind.get("reference"), ind["id"]))
        else:
            self.conn.execute(
                """INSERT INTO indicators (id,type,value,first_seen,last_seen,sources,confidence,malware,
                   threat_type,tags,reference) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (ind["id"], ind["type"], ind["value"], ind.get("first_seen") or now(),
                 ind.get("last_seen") or now(), json.dumps(ind.get("sources", [])),
                 ind.get("confidence", 50), ind.get("malware"), ind.get("threat_type"),
                 json.dumps(ind.get("tags", [])), ind.get("reference")))
        return ind["id"]

    def upsert_advisory(self, adv: dict) -> bool:
        """Returns True if new."""
        existing = self.one("SELECT id FROM advisories WHERE id=?", (adv["id"],))
        vals = (adv["source"], adv["title"], adv.get("summary", ""), adv.get("url", ""),
                adv.get("published") or now(), adv.get("severity", "medium"),
                json.dumps(sorted(set(adv.get("cves", [])))), json.dumps(sorted(set(adv.get("tags", [])))),
                json.dumps(sorted(set(adv.get("malware", [])))))
        if existing:
            self.conn.execute("""UPDATE advisories SET source=?,title=?,summary=?,url=?,published=?,severity=?,
                                 cves=?,tags=?,malware=? WHERE id=?""", vals + (adv["id"],))
            return False
        self.conn.execute("""INSERT INTO advisories (source,title,summary,url,published,severity,cves,tags,malware,
                             id,collected) VALUES (?,?,?,?,?,?,?,?,?,?,?)""", vals + (adv["id"], now()))
        return True

    def link(self, advisory_id: str, indicator_id: str):
        self.conn.execute("INSERT OR IGNORE INTO advisory_indicators VALUES (?,?)", (advisory_id, indicator_id))

    def upsert_vuln(self, v: dict):
        cur = self.one("SELECT * FROM vulns WHERE cve=?", (v["cve"],)) or {}
        merged = {**cur, **{k: val for k, val in v.items() if val not in (None, "")}}
        cols = ["cve", "description", "cvss", "cvss_vector", "epss", "epss_pct", "kev", "kev_added", "kev_due",
                "kev_action", "vendor", "product", "ransomware", "published", "risk"]
        self.conn.execute(f"INSERT OR REPLACE INTO vulns ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                          tuple(merged.get(c) for c in cols))

    def log_run(self, source, started, status, advisories=0, indicators=0, message=""):
        self.conn.execute("INSERT INTO runs (source,started,finished,status,advisories,indicators,message) "
                          "VALUES (?,?,?,?,?,?,?)", (source, started, now(), status, advisories, indicators, message))
        self.commit()
