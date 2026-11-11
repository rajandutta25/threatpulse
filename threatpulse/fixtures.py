"""Offline SAMPLE data in each upstream feed's real response format.

Everything here is fictitious: CVE-2099-* IDs, RFC 5737 documentation IPs and the reserved
.test TLD, so nothing can be mistaken for live intelligence. Used by `demo` and the test suite.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

N = datetime.now(timezone.utc)
d = lambda days, fmt="%Y-%m-%d": (N - timedelta(days=days)).strftime(fmt)  # noqa: E731

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2099-1001", "vendorProject": "Fortinet", "product": "FortiOS SSL-VPN",
     "vulnerabilityName": "SAMPLE FortiOS Heap Overflow", "dateAdded": d(1),
     "shortDescription": "SAMPLE: heap-based buffer overflow in SSL-VPN allows unauthenticated RCE.",
     "requiredAction": "Apply mitigations per vendor instructions or discontinue use of the product.",
     "dueDate": d(-20), "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2099-1002", "vendorProject": "ExampleSoft", "product": "FileShare Gateway",
     "vulnerabilityName": "SAMPLE Path Traversal", "dateAdded": d(2),
     "shortDescription": "SAMPLE: path traversal leading to arbitrary file read.",
     "requiredAction": "Apply vendor updates.", "dueDate": d(-19), "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2099-0007", "vendorProject": "OldCorp", "product": "Legacy CMS",
     "vulnerabilityName": "SAMPLE old entry", "dateAdded": d(400), "shortDescription": "SAMPLE old.",
     "requiredAction": "Apply updates.", "dueDate": d(380), "knownRansomwareCampaignUse": "Unknown"},
]}

NVD = {
    "CVE-2099-1001": 9.8, "CVE-2099-1002": 7.5, "CVE-2099-2001": 8.8, "CVE-2099-0007": 6.1,
}

EPSS = {"CVE-2099-1001": (0.94, 0.999), "CVE-2099-1002": (0.41, 0.97), "CVE-2099-2001": (0.12, 0.93),
        "CVE-2099-0007": (0.01, 0.4)}

FEODO = [
    {"ip_address": "198.51.100.23", "port": 443, "status": "online", "malware": "QakBot",
     "first_seen": d(3, "%Y-%m-%d %H:%M:%S"), "last_online": d(0)},
    {"ip_address": "198.51.100.77", "port": 8443, "status": "online", "malware": "Pikabot",
     "first_seen": d(2, "%Y-%m-%d %H:%M:%S"), "last_online": d(0)},
    {"ip_address": "10.1.2.3", "port": 443, "status": "online", "malware": "QakBot",  # private -> filtered
     "first_seen": d(2, "%Y-%m-%d %H:%M:%S"), "last_online": d(0)},
]

THREATFOX = {"query_status": "ok", "data": [
    {"id": "1", "ioc": "203.0.113.50:4444", "ioc_type": "ip:port", "threat_type": "botnet_cc",
     "malware_printable": "LummaStealer", "confidence_level": 100, "first_seen": d(1, "%Y-%m-%d %H:%M:%S UTC"),
     "tags": ["Lumma", "stealer"], "reference": None},
    {"id": "2", "ioc": "lumma-panel.test", "ioc_type": "domain", "threat_type": "botnet_cc",
     "malware_printable": "LummaStealer", "confidence_level": 90, "first_seen": d(1, "%Y-%m-%d %H:%M:%S UTC"),
     "tags": ["Lumma"], "reference": None},
    {"id": "3", "ioc": "a" * 64, "ioc_type": "sha256_hash", "threat_type": "payload",
     "malware_printable": "LummaStealer", "confidence_level": 75, "first_seen": d(1, "%Y-%m-%d %H:%M:%S UTC"),
     "tags": ["Lumma"], "reference": None},
    {"id": "4", "ioc": "qbot-cdn.test", "ioc_type": "domain", "threat_type": "payload_delivery",
     "malware_printable": "QakBot", "confidence_level": 80, "first_seen": d(2, "%Y-%m-%d %H:%M:%S UTC"),
     "tags": ["qakbot"], "reference": None},
]}

URLHAUS = {"query_status": "ok", "urls": [
    {"url": "http://198.51.100.99/bins/mozi.m", "url_status": "online", "threat": "malware_download",
     "tags": ["Mozi", "elf"], "date_added": d(0, "%Y-%m-%d %H:%M:%S UTC"), "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"},
    {"url": "https://invoice-docs.test/download/inv_2099.zip", "url_status": "online", "threat": "malware_download",
     "tags": ["QakBot", "zip"], "date_added": d(1, "%Y-%m-%d %H:%M:%S UTC"), "urlhaus_reference": "https://urlhaus.abuse.ch/url/2/"},
    {"url": "http://dead.test/x.exe", "url_status": "offline", "threat": "malware_download", "tags": [],
     "date_added": d(1, "%Y-%m-%d %H:%M:%S UTC")},
]}

OTX = {"results": [{
    "id": "sample0001", "name": "SAMPLE: Ransomware affiliate exploits FortiOS SSL-VPN (CVE-2099-1001)",
    "description": "SAMPLE pulse. Affiliate gains access through CVE-2099-1001, deploys Cobalt Strike, exfiltrates "
                   "with rclone and encrypts ESXi hosts. Techniques T1190, T1059.001, T1486.",
    "author_name": "SampleLabs", "created": d(1, "%Y-%m-%dT%H:%M:%S"), "adversary": "SAMPLE-SPIDER",
    "malware_families": ["Cobalt Strike"], "attack_ids": ["T1190", "T1486"], "tags": ["ransomware", "fortinet"],
    "indicators": [
        {"type": "IPv4", "indicator": "203.0.113.10", "created": d(1, "%Y-%m-%dT%H:%M:%S")},
        {"type": "domain", "indicator": "cs-beacon.test", "created": d(1, "%Y-%m-%dT%H:%M:%S")},
        {"type": "FileHash-SHA256", "indicator": "b" * 64, "created": d(1, "%Y-%m-%dT%H:%M:%S")},
        {"type": "CVE", "indicator": "CVE-2099-1001", "created": d(1, "%Y-%m-%dT%H:%M:%S")},
    ]}], "next": None}

RSS = f"""<?xml version="1.0"?><rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
<channel><title>SAMPLE Vendor Blog</title>
<item><title>SAMPLE: LummaStealer spreads via fake CAPTCHA pages</title>
<link>https://blog.test/lumma-captcha</link><pubDate>{format_datetime(N - timedelta(hours=6))}</pubDate>
<category>infostealer</category>
<description><![CDATA[<p>SAMPLE write-up. Victims are lured to hxxps://verify-human[.]test/captcha and told to paste a
PowerShell command. The payload (SHA256 {"c" * 64}) beacons to 203[.]0[.]113[.]50 and lumma-panel[.]test.
Phishing emails came from billing@invoice-docs[.]test. Analysis also references microsoft.com (benign) and
the dropper payload.exe.</p>]]></description></item>
<item><title>SAMPLE: Critical RCE in ExampleSoft FileShare Gateway exploited (CVE-2099-1002, CVE-2099-2001)</title>
<link>https://blog.test/fileshare-0day</link><pubDate>{format_datetime(N - timedelta(days=1))}</pubDate>
<description>SAMPLE. Actively exploited zero-day. Exploitation traffic from 192.0.2.44 and 192.0.2.45.
Webshell dropped at /aspnet_client/x.aspx (MD5 {"d" * 32}).</description></item>
<item><title>SAMPLE: Old news</title><link>https://blog.test/old</link>
<pubDate>{format_datetime(N - timedelta(days=60))}</pubDate><description>old</description></item>
</channel></rss>"""


class FixtureHTTP:
    offline = True

    def get_json(self, url, headers=None, params=None):
        if "known_exploited" in url:
            return KEV
        if "feodotracker" in url:
            return FEODO
        if "urlhaus" in url:
            return URLHAUS
        if "otx.alienvault" in url:
            return OTX
        if "first.org" in url:
            cves = (params or {}).get("cve", "").split(",")
            return {"data": [{"cve": c, "epss": str(EPSS[c][0]), "percentile": str(EPSS[c][1])}
                             for c in cves if c in EPSS]}
        if "nvd.nist.gov" in url:
            c = (params or {}).get("cveId")
            if c not in NVD:
                return {"vulnerabilities": []}
            return {"vulnerabilities": [{"cve": {"id": c, "published": d(5, "%Y-%m-%dT%H:%M:%S.000"),
                                                 "descriptions": [{"lang": "en", "value": f"SAMPLE NVD description for {c}"}],
                                                 "metrics": {"cvssMetricV31": [{"cvssData": {
                                                     "baseScore": NVD[c], "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]}
        raise RuntimeError(f"no fixture for {url}")

    def post_json(self, url, payload, headers=None):
        if "threatfox" in url:
            return THREATFOX
        return {"ok": True}

    def get_text(self, url, headers=None):
        if url.startswith("fixture://rss"):
            return RSS
        raise RuntimeError(f"no fixture for {url}")
