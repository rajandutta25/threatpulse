"""Configuration loading: config.toml + environment variable overrides."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_RSS = [
    {"name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "full_text": True},
    {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed_full.xml", "full_text": False},
    {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "full_text": True},
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/", "full_text": True},
    {"name": "The DFIR Report", "url": "https://thedfirreport.com/feed/", "full_text": True},
    {"name": "Microsoft Security Blog", "url": "https://www.microsoft.com/en-us/security/blog/feed/", "full_text": False},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "full_text": False},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "full_text": False},
]

DEFAULT_ALLOW_DOMAINS = [
    "microsoft.com", "google.com", "github.com", "cisa.gov", "nist.gov", "mitre.org",
    "virustotal.com", "abuse.ch", "twitter.com", "x.com", "linkedin.com", "facebook.com",
    "youtube.com", "apple.com", "amazon.com", "cloudflare.com", "w3.org", "schema.org",
    "paloaltonetworks.com", "talosintelligence.com", "cisco.com", "bleepingcomputer.com",
    "thehackernews.com", "sans.edu", "thedfirreport.com", "first.org", "alienvault.com",
    "wordpress.org", "gravatar.com", "feedburner.com", "example.com", "example.org",
]


@dataclass
class Config:
    db_path: str = "data/threatpulse.db"
    lookback_days: int = 7
    user_agent: str = "ThreatPulse/1.0 (+https://github.com/your-org/threatpulse)"
    http_timeout: int = 30
    watch_vendors: list[str] = field(default_factory=list)
    watch_products: list[str] = field(default_factory=list)
    sources: dict = field(default_factory=dict)
    rss_feeds: list[dict] = field(default_factory=lambda: list(DEFAULT_RSS))
    allow_domains: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOW_DOMAINS))
    allow_cidrs: list[str] = field(default_factory=list)
    webhook_url: str = ""
    notify_min_score: int = 75
    otx_key: str = ""
    abusech_key: str = ""
    nvd_key: str = ""
    permit_test_ranges: bool = False  # demo/tests only: allow RFC 5737 documentation IPs

    def source_enabled(self, name: str) -> bool:
        return bool(self.sources.get(name, {}).get("enabled", True))


def load_config(path: str | None = None) -> Config:
    path = path or os.environ.get("TP_CONFIG", "config.toml")
    cfg = Config()
    p = Path(path)
    if p.exists():
        data = tomllib.loads(p.read_text())
        g = data.get("general", {})
        cfg.db_path = g.get("db_path", cfg.db_path)
        cfg.lookback_days = int(g.get("lookback_days", cfg.lookback_days))
        cfg.user_agent = g.get("user_agent", cfg.user_agent)
        cfg.http_timeout = int(g.get("http_timeout", cfg.http_timeout))
        w = data.get("watchlist", {})
        cfg.watch_vendors = [v.lower() for v in w.get("vendors", [])]
        cfg.watch_products = [v.lower() for v in w.get("products", [])]
        cfg.sources = data.get("sources", {})
        if "rss" in data and "feeds" in data["rss"]:
            cfg.rss_feeds = data["rss"]["feeds"]
        a = data.get("allowlist", {})
        cfg.allow_domains = list(set(cfg.allow_domains) | set(a.get("domains", [])))
        cfg.allow_cidrs = a.get("cidrs", [])
        n = data.get("notify", {})
        cfg.webhook_url = n.get("webhook_url", "")
        cfg.notify_min_score = int(n.get("min_score", cfg.notify_min_score))
        k = data.get("keys", {})
        cfg.otx_key, cfg.abusech_key, cfg.nvd_key = k.get("otx", ""), k.get("abusech", ""), k.get("nvd", "")
    # env overrides (preferred for secrets)
    cfg.otx_key = os.environ.get("TP_OTX_KEY", cfg.otx_key)
    cfg.abusech_key = os.environ.get("TP_ABUSECH_KEY", cfg.abusech_key)
    cfg.nvd_key = os.environ.get("TP_NVD_KEY", cfg.nvd_key)
    cfg.webhook_url = os.environ.get("TP_WEBHOOK_URL", cfg.webhook_url)
    cfg.db_path = os.environ.get("TP_DB_PATH", cfg.db_path)
    return cfg
