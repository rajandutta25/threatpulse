import json

import pytest
from fastapi.testclient import TestClient

from threatpulse import detections, exporters, pipeline
from threatpulse.api import create_app
from threatpulse.config import Config
from threatpulse.db import DB
from threatpulse.fixtures import FixtureHTTP
from threatpulse.ioc import Allowlist, classify, extract, refang


# ---------------- IOC engine ----------------
def test_refang():
    assert refang("hxxps://evil[.]test/a") == "https://evil.test/a"
    assert refang("1(.)2[.]3{.}4") == "1.2.3.4"
    assert refang("bad[at]evil[dot]test") == "bad@evil.test"


def test_extract_filters_noise():
    text = ("C2 at 8.8.4[.]4 and 10.0.0.1, url hxxp://bad-host[.]xyz/p.php, drops payload.exe, "
            "see microsoft.com. hash " + "e" * 64 + " CVE-2024-3400")
    out = extract(text, Allowlist(["microsoft.com"]))
    assert out["ipv4"] == {"8.8.4.4"}               # private IP dropped
    assert out["url"] == {"http://bad-host.xyz/p.php"}
    assert "payload.exe" not in out["domain"]        # file name is not a domain
    assert "microsoft.com" not in out["domain"]       # allowlisted
    assert "bad-host.xyz" not in out["domain"]        # not double-counted from URL
    assert out["sha256"] == {"e" * 64} and not out["md5"]
    assert out["cve"] == {"CVE-2024-3400"}


@pytest.mark.parametrize("v,t", [("1.2.3.4", "ipv4"), ("evil.xyz", "domain"), ("http://a.xyz/b", "url"),
                                 ("a" * 32, "md5"), ("a" * 40, "sha1"), ("a" * 64, "sha256"),
                                 ("x@evil.xyz", "email"), ("notes.txt", None)])
def test_classify(v, t):
    assert classify(v) == t


# ---------------- pipeline ----------------
@pytest.fixture(scope="module")
def loaded():
    cfg = Config(db_path=":memory:", permit_test_ranges=True, otx_key="x", abusech_key="x",
                 watch_vendors=["fortinet", "microsoft"])
    cfg.rss_feeds = [{"name": "SAMPLE Vendor Blog", "url": "fixture://rss", "full_text": False}]
    db = DB(":memory:")
    summary = pipeline.run(cfg, db, FixtureHTTP())
    return cfg, db, summary


def test_pipeline_runs_all_sources(loaded):
    _, db, summary = loaded
    for src in ("cisa_kev", "rss", "otx", "threatfox", "urlhaus", "feodo"):
        assert summary[src].startswith("ok"), summary
    assert db.one("SELECT COUNT(*) n FROM advisories")["n"] == 5  # old KEV + old RSS item excluded
    assert not db.q("SELECT * FROM indicators WHERE value='10.1.2.3'")  # private filtered
    assert not db.q("SELECT * FROM indicators WHERE value LIKE '%dead.test%'")  # offline URL dropped


def test_enrichment_and_kev(loaded):
    _, db, _ = loaded
    v = db.one("SELECT * FROM vulns WHERE cve='CVE-2099-1001'")
    assert v["kev"] == 1 and v["ransomware"] == 1 and v["cvss"] == 9.8 and v["epss"] == 0.94
    assert v["risk"] >= 90


def test_multi_source_corroboration(loaded):
    _, db, _ = loaded
    i = db.one("SELECT * FROM indicators WHERE value='203.0.113.50'")
    assert set(i["sources"]) == {"SAMPLE Vendor Blog", "ThreatFox"}
    assert i["malware"] == "LummaStealer"
    assert i["score"] > db.one("SELECT score FROM indicators WHERE value='192.0.2.44'")["score"]


def test_correlation_by_malware_family(loaded):
    _, db, _ = loaded
    a = db.one("SELECT * FROM advisories WHERE title LIKE '%LummaStealer%'")
    assert a["malware"] == ["LummaStealer"]
    linked = {r["value"] for r in db.q("SELECT i.value FROM indicators i JOIN advisory_indicators l "
                                       "ON l.indicator_id=i.id WHERE l.advisory_id=?", (a["id"],))}
    assert "a" * 64 in linked  # ThreatFox hash pulled in via family name


def test_relevance_and_actions(loaded):
    _, db, _ = loaded
    kev = db.one("SELECT * FROM advisories WHERE id='kev-CVE-2099-1001'")
    assert kev["relevant"] == 1 and kev["score"] >= 90
    cats = [(a["priority"], a["category"]) for a in kev["actions"]]
    assert ("P1", "Patch") in cats and ("P1", "Hunt") in cats
    lumma = db.one("SELECT * FROM advisories WHERE title LIKE '%LummaStealer%'")
    assert lumma["relevant"] == 0  # "microsoft.com" mention must not flag Microsoft
    assert any(x["category"] == "Block" for x in lumma["actions"])


# ---------------- detections & exports ----------------
def test_detections(loaded):
    _, db, _ = loaded
    inds = db.q("SELECT * FROM indicators")
    det = detections.generate(inds, "Test advisory")
    assert "DeviceNetworkEvents" in det["kql"] and "let tp_ips" in det["kql"]
    assert "rule tp_test_advisory" in det["chronicle_yaral"] and "$e.target.ip" in det["chronicle_yaral"]
    assert "dns.query" in det["suricata"] and "sid:" in det["suricata"]
    assert "logsource:" in det["sigma"]
    assert "dest_ip IN" in det["splunk"]


def test_stix_valid(loaded):
    stix2 = pytest.importorskip("stix2")
    _, db, _ = loaded
    inds = db.q("SELECT * FROM indicators")
    advs = db.q("SELECT * FROM advisories")
    vulns = db.q("SELECT * FROM vulns")
    links = {a["id"]: [r["indicator_id"] for r in db.q("SELECT indicator_id FROM advisory_indicators "
                                                        "WHERE advisory_id=?", (a["id"],))] for a in advs}
    bundle = exporters.stix_bundle(inds, advs, links, vulns)
    parsed = stix2.parse(json.dumps(bundle), allow_custom=False)
    assert len(parsed.objects) == 1 + len(inds) + len(vulns) + len(advs)


def test_api(loaded):
    cfg, db, _ = loaded
    c = TestClient(create_app(cfg, db, FixtureHTTP()))
    s = c.get("/api/stats").json()
    assert s["advisories"] == 5 and s["kev"] >= 2
    advs = c.get("/api/advisories?min_score=70").json()
    assert advs and advs[0]["score"] >= advs[-1]["score"]
    detail = c.get(f"/api/advisories/{advs[0]['id']}").json()
    assert detail["actions"] and "detections" in detail
    assert c.get("/api/lookup", params={"value": "203[.]0[.]113[.]50"}).json()["found"]
    assert c.get("/api/lookup", params={"value": "CVE-2099-1001"}).json()["vuln"]["kev"] == 1
    edl = c.get("/api/export/edl/ipv4?min_score=0").text
    assert "203.0.113.50" in edl
    assert c.get("/api/export/suricata?min_score=0").text.startswith("# ThreatPulse")
    assert c.get("/api/export/stix?min_score=0").json()["type"] == "bundle"
    assert c.get("/").status_code == 200


def test_static_site(loaded, tmp_path):
    from threatpulse.sitegen import build
    _, db, _ = loaded
    r = build(db, str(tmp_path / "site"), repo_url="https://github.com/x/y")
    s = tmp_path / "site"
    assert r["advisories"] == 5 and (s / "index.html").read_text().count("window.TP_STATIC=true") == 1
    meta = json.loads((s / "data" / "meta.json").read_text())
    assert meta["repo"] == "https://github.com/x/y" and meta["stats"]["kev"] >= 2
    advs = json.loads((s / "data" / "advisories.json").read_text())
    for a in advs:
        d = json.loads((s / "data" / "advisory" / f"{a['id']}.json").read_text())
        assert "detections" in d and "actions" in d
    assert "203.0.113.50" in (s / "feeds" / "ipv4.txt").read_text()
    assert json.loads((s / "feeds" / "stix.json").read_text())["type"] == "bundle"


def test_prune(loaded):
    from threatpulse.pipeline import prune
    _, db, _ = loaded
    db.conn.execute("INSERT INTO indicators (id,type,value,last_seen) VALUES ('old','ipv4','8.8.8.8','2000-01-01T00:00:00Z')")
    assert prune(db, 90) >= 1 and not db.one("SELECT id FROM indicators WHERE id='old'")
