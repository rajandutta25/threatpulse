"""Feed collectors. Each collector returns a Batch of advisories, indicators and vuln records.

Every collector takes an injected `http` object (see HTTP below) so it can be tested
offline with fixtures and swapped for a proxy-aware client in production.
"""
from __future__ import annotations

import hashlib
import html
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import httpx

from .config import Config
from .ioc import Allowlist, classify, extract, ioc_id

UTC = timezone.utc


@dataclass
class Batch:
    source: str
    advisories: list[dict] = field(default_factory=list)  # each may carry "indicators": [...]
    indicators: list[dict] = field(default_factory=list)  # standalone feed IOCs
    vulns: list[dict] = field(default_factory=list)


class HTTP:
    def __init__(self, cfg: Config):
        self.client = httpx.Client(timeout=cfg.http_timeout, follow_redirects=True,
                                   headers={"User-Agent": cfg.user_agent})

    def get_json(self, url, headers=None, params=None):
        r = self.client.get(url, headers=headers, params=params)
        r.raise_for_status()
        return r.json()

    def post_json(self, url, payload, headers=None):
        r = self.client.post(url, json=payload, headers=headers)
        r.raise_for_status()
        return r.json()

    def get_text(self, url, headers=None):
        r = self.client.get(url, headers=headers)
        r.raise_for_status()
        return r.text


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_date(s: str | None) -> str:
    if not s:
        return _iso(datetime.now(UTC))
    s = s.strip()
    for fn in (lambda x: datetime.fromisoformat(x.replace("Z", "+00:00")), parsedate_to_datetime,
               lambda x: datetime.strptime(x, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=UTC),
               lambda x: datetime.strptime(x, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC),
               lambda x: datetime.strptime(x, "%Y-%m-%d").replace(tzinfo=UTC)):
        try:
            d = fn(s)
            return _iso(d if d.tzinfo else d.replace(tzinfo=UTC))
        except Exception:
            continue
    return _iso(datetime.now(UTC))


def _hid(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:16]


def _ind(type_, value, source, confidence=50, **kw) -> dict:
    value = value.strip()
    if type_ in ("domain", "sha256", "sha1", "md5", "email"):
        value = value.lower()
    return {"id": ioc_id(type_, value), "type": type_, "value": value, "sources": [source],
            "confidence": confidence, **kw}


def strip_html(s: str) -> str:
    s = re.sub(r"(?is)<(script|style|nav|footer|header).*?</\1>", " ", s or "")
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", html.unescape(s)).strip()


# --------------------------------------------------------------------------------------
class Collector:
    name = "base"

    def __init__(self, cfg: Config, http):
        self.cfg, self.http = cfg, http
        self.allow = Allowlist(cfg.allow_domains, cfg.allow_cidrs, cfg.permit_test_ranges)
        self.since = datetime.now(UTC) - timedelta(days=cfg.lookback_days)

    def available(self) -> tuple[bool, str]:
        return True, ""

    def collect(self) -> Batch:
        raise NotImplementedError


class CisaKev(Collector):
    """CISA Known Exploited Vulnerabilities — the single most actionable patch signal."""
    name = "cisa_kev"
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def collect(self) -> Batch:
        data = self.http.get_json(self.URL)
        b = Batch(self.name)
        for v in data.get("vulnerabilities", []):
            ransomware = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
            b.vulns.append({"cve": v["cveID"], "description": v.get("shortDescription"), "kev": 1,
                            "kev_added": v.get("dateAdded"), "kev_due": v.get("dueDate"),
                            "kev_action": v.get("requiredAction"), "vendor": v.get("vendorProject"),
                            "product": v.get("product"), "ransomware": int(ransomware)})
            added = _parse_date(v.get("dateAdded"))
            if added >= _iso(self.since):
                b.advisories.append({
                    "id": "kev-" + v["cveID"], "source": "CISA KEV",
                    "title": f"Actively exploited: {v.get('vendorProject')} {v.get('product')} — "
                             f"{v.get('vulnerabilityName', v['cveID'])}",
                    "summary": f"{v.get('shortDescription', '')} Required action: {v.get('requiredAction', '')} "
                               f"Federal due date: {v.get('dueDate')}.",
                    "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}", "published": added,
                    "severity": "critical" if ransomware else "high", "cves": [v["cveID"]],
                    "tags": ["exploited-in-the-wild"] + (["ransomware"] if ransomware else []),
                })
        return b


class Epss(Collector):
    """FIRST EPSS — probability of exploitation in the next 30 days. Enriches known CVEs."""
    name = "epss"
    URL = "https://api.first.org/data/v1/epss"

    def __init__(self, cfg, http, cves: list[str] | None = None):
        super().__init__(cfg, http)
        self.cves = cves or []

    def collect(self) -> Batch:
        b = Batch(self.name)
        for i in range(0, len(self.cves), 100):
            chunk = self.cves[i:i + 100]
            data = self.http.get_json(self.URL, params={"cve": ",".join(chunk)})
            for row in data.get("data", []):
                b.vulns.append({"cve": row["cve"], "epss": float(row["epss"]), "epss_pct": float(row["percentile"])})
        return b


class Nvd(Collector):
    """NVD CVE API 2.0 — CVSS + descriptions for CVEs we've seen (rate-limit aware)."""
    name = "nvd"
    URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, cfg, http, cves: list[str] | None = None, limit: int = 40):
        super().__init__(cfg, http)
        self.cves = (cves or [])[: (limit if not cfg.nvd_key else limit * 5)]

    def collect(self) -> Batch:
        import time
        b = Batch(self.name)
        headers = {"apiKey": self.cfg.nvd_key} if self.cfg.nvd_key else None
        delay = 0.7 if self.cfg.nvd_key else 6.2  # NVD: 5 req/30s without key, 50 with key
        for n, cve in enumerate(self.cves):
            if n and not getattr(self.http, "offline", False):
                time.sleep(delay)
            try:
                data = self.http.get_json(self.URL, headers=headers, params={"cveId": cve})
            except Exception:
                continue
            for item in data.get("vulnerabilities", []):
                b.vulns.append(self.parse(item["cve"]))
        return b

    @staticmethod
    def parse(c: dict) -> dict:
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        cvss, vector = None, None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m = c.get("metrics", {}).get(key)
            if m:
                cvss = m[0]["cvssData"].get("baseScore")
                vector = m[0]["cvssData"].get("vectorString")
                break
        return {"cve": c["id"], "description": desc, "cvss": cvss, "cvss_vector": vector,
                "published": _parse_date(c.get("published"))}


class FeodoTracker(Collector):
    """abuse.ch Feodo Tracker — botnet C2 IPs (QakBot, Emotet, Pikabot, etc.). No key needed."""
    name = "feodo"
    URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    def collect(self) -> Batch:
        b = Batch(self.name)
        for r in self.http.get_json(self.URL):
            ip = r.get("ip_address")
            if not ip or not self.allow.ip_ok(ip):
                continue
            b.indicators.append(_ind("ipv4", ip, "Feodo Tracker", 90, malware=r.get("malware"),
                                     threat_type="botnet_c2", first_seen=_parse_date(r.get("first_seen")),
                                     # presence on Feodo's current blocklist means the C2 is active now
                                     last_seen=_iso(datetime.now(UTC)),
                                     tags=[f"port:{r.get('port')}", str(r.get("status", ""))],
                                     reference="https://feodotracker.abuse.ch/browse/host/" + ip))
        return b


class ThreatFox(Collector):
    """abuse.ch ThreatFox — community IOCs tagged with malware family. Requires free Auth-Key."""
    name = "threatfox"
    URL = "https://threatfox-api.abuse.ch/api/v1/"
    TYPE_MAP = {"ip:port": "ipv4", "domain": "domain", "url": "url", "md5_hash": "md5",
                "sha1_hash": "sha1", "sha256_hash": "sha256"}

    def available(self):
        return (bool(self.cfg.abusech_key), "set TP_ABUSECH_KEY (free at auth.abuse.ch)")

    def collect(self) -> Batch:
        b = Batch(self.name)
        days = min(self.cfg.lookback_days, 7)
        data = self.http.post_json(self.URL, {"query": "get_iocs", "days": days},
                                   headers={"Auth-Key": self.cfg.abusech_key})
        for r in data.get("data") or []:
            t = self.TYPE_MAP.get(r.get("ioc_type"))
            if not t:
                continue
            val = r["ioc"].split(":")[0] if t == "ipv4" else r["ioc"]
            if t == "ipv4" and not self.allow.ip_ok(val):
                continue
            if t == "domain" and not self.allow.domain_ok(val):
                continue
            b.indicators.append(_ind(t, val, "ThreatFox", int(r.get("confidence_level") or 50),
                                     malware=r.get("malware_printable"), threat_type=r.get("threat_type"),
                                     first_seen=_parse_date(r.get("first_seen")),
                                     tags=(r.get("tags") or []) + ([f"port:{r['ioc'].split(':')[1]}"] if t == "ipv4" and ":" in r["ioc"] else []),
                                     reference=r.get("reference") or f"https://threatfox.abuse.ch/ioc/{r.get('id')}"))
        return b


class UrlHaus(Collector):
    """abuse.ch URLhaus — malware distribution URLs. Requires free Auth-Key."""
    name = "urlhaus"
    URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"

    def available(self):
        return (bool(self.cfg.abusech_key), "set TP_ABUSECH_KEY (free at auth.abuse.ch)")

    def collect(self) -> Batch:
        b = Batch(self.name)
        data = self.http.get_json(self.URL, headers={"Auth-Key": self.cfg.abusech_key})
        for r in data.get("urls") or []:
            if r.get("url_status") == "offline":
                continue
            tags = r.get("tags") or []
            b.indicators.append(_ind("url", r["url"], "URLhaus", 80, threat_type=r.get("threat", "malware_download"),
                                     malware=tags[0] if tags else None, tags=tags,
                                     first_seen=_parse_date(r.get("date_added")), reference=r.get("urlhaus_reference")))
        return b


class Otx(Collector):
    """AlienVault OTX subscribed pulses — campaign reports with attached IOCs."""
    name = "otx"
    URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    TYPE_MAP = {"IPv4": "ipv4", "domain": "domain", "hostname": "domain", "URL": "url",
                "FileHash-MD5": "md5", "FileHash-SHA1": "sha1", "FileHash-SHA256": "sha256", "email": "email"}

    def available(self):
        return (bool(self.cfg.otx_key), "set TP_OTX_KEY (free at otx.alienvault.com)")

    def collect(self) -> Batch:
        b = Batch(self.name)
        url, pages = self.URL, 0
        params = {"modified_since": _iso(self.since), "limit": 50}
        while url and pages < 10:
            data = self.http.get_json(url, headers={"X-OTX-API-KEY": self.cfg.otx_key}, params=params)
            for p in data.get("results", []):
                inds = []
                for i in p.get("indicators", []):
                    t = self.TYPE_MAP.get(i.get("type"))
                    if not t:
                        continue
                    v = i["indicator"]
                    if t == "ipv4" and not self.allow.ip_ok(v):
                        continue
                    if t == "domain" and not self.allow.domain_ok(v):
                        continue
                    inds.append(_ind(t, v, "OTX", 65, malware=(p.get("malware_families") or [None])[0]
                                     if isinstance((p.get("malware_families") or [None])[0], str) else None,
                                     first_seen=_parse_date(i.get("created")),
                                     reference=f"https://otx.alienvault.com/pulse/{p['id']}"))
                mal = [m if isinstance(m, str) else m.get("display_name", "") for m in p.get("malware_families", [])]
                cves = sorted({c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", " ".join(
                    [p.get("description", "")] + [i["indicator"] for i in p.get("indicators", []) if i.get("type") == "CVE"]), re.I)})
                b.advisories.append({
                    "id": "otx-" + p["id"], "source": "OTX: " + (p.get("author_name") or "community"),
                    "title": p.get("name", "OTX pulse"), "summary": (p.get("description") or "")[:2000],
                    "url": f"https://otx.alienvault.com/pulse/{p['id']}", "published": _parse_date(p.get("created")),
                    "severity": "high" if p.get("adversary") or mal else "medium", "cves": cves,
                    "tags": (p.get("tags") or [])[:15] + ([f"actor:{p['adversary']}"] if p.get("adversary") else [])
                            + [f"attack:{a}" for a in (p.get("attack_ids") or []) if isinstance(a, str)],
                    "malware": [m for m in mal if m], "indicators": inds,
                })
            url, params, pages = data.get("next"), None, pages + 1
        return b


class Rss(Collector):
    """Vendor/government/news advisories via RSS/Atom, with IOC + CVE extraction from text."""
    name = "rss"
    NS = {"atom": "http://www.w3.org/2005/Atom", "content": "http://purl.org/rss/1.0/modules/content/"}
    SEV_WORDS = {"critical": ["zero-day", "0-day", "actively exploited", "ransomware", "emergency directive",
                              "exploited in the wild", "wormable", "critical"],
                 "high": ["exploit", "backdoor", "apt", "malware", "botnet", "breach", "rce", "remote code execution",
                          "supply chain", "phishing campaign", "infostealer"]}

    def collect(self) -> Batch:
        b = Batch(self.name)
        for feed in self.cfg.rss_feeds:
            try:
                xml = self.http.get_text(feed["url"])
                for item in self.parse(xml):
                    if item["published"] < _iso(self.since):
                        continue
                    text = item["text"]
                    if feed.get("full_text") and item["url"]:
                        try:
                            text += " " + strip_html(self.http.get_text(item["url"]))
                        except Exception:
                            pass
                    b.advisories.append(self.to_advisory(feed["name"], item, text))
            except Exception as e:  # one bad feed must not kill the run
                b.advisories.append({"_error": f"{feed['name']}: {e}"})
        b.advisories = [a for a in b.advisories if "_error" not in a]
        return b

    def parse(self, xml: str) -> list[dict]:
        root = ET.fromstring(xml.encode() if isinstance(xml, str) else xml)
        items = []
        for it in root.iter("item"):
            content = it.find("content:encoded", self.NS)
            items.append({"title": (it.findtext("title") or "").strip(), "url": (it.findtext("link") or "").strip(),
                          "published": _parse_date(it.findtext("pubDate")),
                          "text": strip_html((it.findtext("description") or "") + " " +
                                             (content.text if content is not None and content.text else "")),
                          "categories": [c.text for c in it.findall("category") if c.text]})
        for it in root.iter("{http://www.w3.org/2005/Atom}entry"):
            link = it.find("atom:link", self.NS)
            items.append({"title": (it.findtext("atom:title", "", self.NS)).strip(),
                          "url": link.get("href") if link is not None else "",
                          "published": _parse_date(it.findtext("atom:updated", None, self.NS)
                                                   or it.findtext("atom:published", None, self.NS)),
                          "text": strip_html((it.findtext("atom:summary", "", self.NS)) + " " +
                                             (it.findtext("atom:content", "", self.NS))),
                          "categories": [c.get("term") for c in it.findall("atom:category", self.NS) if c.get("term")]})
        return items

    def severity(self, text: str) -> str:
        low = text.lower()
        for sev, words in self.SEV_WORDS.items():
            if any(w in low for w in words):
                return sev
        return "medium"

    def to_advisory(self, feed_name: str, item: dict, text: str) -> dict:
        iocs = extract(text, self.allow)
        inds = []
        for t, vals in iocs.items():
            if t == "cve":
                continue
            for v in list(vals)[:500]:
                inds.append(_ind(t, v, feed_name, 55, reference=item["url"], first_seen=item["published"]))
        summary = item["text"][:1200]
        return {"id": "rss-" + _hid(item["url"] or item["title"]), "source": feed_name, "title": item["title"],
                "summary": summary, "url": item["url"], "published": item["published"],
                "severity": self.severity(item["title"] + " " + text[:4000]), "cves": sorted(iocs["cve"]),
                "tags": [c for c in item["categories"]][:10], "indicators": inds}


FEED_COLLECTORS = [CisaKev, Rss, Otx, ThreatFox, UrlHaus, FeodoTracker]

__all__ = ["Batch", "HTTP", "Collector", "CisaKev", "Epss", "Nvd", "FeodoTracker", "ThreatFox", "UrlHaus",
           "Otx", "Rss", "FEED_COLLECTORS", "classify"]
