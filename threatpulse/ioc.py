"""IOC extraction, refanging, classification and false-positive filtering."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlparse

# A compact TLD set: enough to avoid matching file names like "payload.exe" as domains.
TLDS = set("""
com net org info biz io co me us uk de ru cn su xyz top online site club shop store live app dev
cloud tech pro link click space website fun icu buzz rest cyou monster sbs bond cfd lol pw tk ml ga cf gq
in ir kp sy ua by kz tr br mx ar cl jp kr tw hk sg my id th vn ph au nz ca fr it es nl be ch at pl cz ro
hu se no fi dk ie pt gr il sa ae qa kw bh om eg za ng ke ma gov edu mil int ws cc tv to ly am la mobi
name asia eu africa news email network systems solutions services support digital zone today world
group agency ltd cam quest work tokyo best life host win download stream gdn men loan date racing
review science party trade webcam bid kim country cricket faith accountant onion test
""".split())

FILE_EXT_NOT_TLD = {"exe", "dll", "zip", "rar", "doc", "docx", "xls", "xlsx", "pdf", "js", "ps1",
                    "bat", "vbs", "lnk", "iso", "img", "msi", "jar", "sh", "py", "php", "html",
                    "htm", "aspx", "jsp", "png", "jpg", "gif", "txt", "log", "dat", "bin", "sys", "tmp"}

RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\)\]]+", re.I)
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
RE_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.I)


def refang(text: str) -> str:
    """Undo common defanging: hxxp, [.], (.), {.}, [dot], [:], [at]."""
    t = re.sub(r"h[xX]{2}p(s?)", r"http\1", text)
    t = re.sub(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*\.\s*\}", ".", t, flags=re.I)
    t = re.sub(r"\[\s*:\s*\]", ":", t)
    t = re.sub(r"\[\s*(?:@|at)\s*\]", "@", t, flags=re.I)
    t = t.replace("[/]", "/").replace(":/ /", "://")
    return t


def defang(value: str) -> str:
    return value.replace("http", "hxxp").replace(".", "[.]")


def ioc_id(ioc_type: str, value: str) -> str:
    return hashlib.sha1(f"{ioc_type}:{value.lower()}".encode()).hexdigest()[:16]


class Allowlist:
    TEST_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

    def __init__(self, domains: list[str] | None = None, cidrs: list[str] | None = None, permit_test: bool = False):
        self.permit_test = permit_test
        self.domains = {d.lower().lstrip(".") for d in (domains or [])}
        self.nets = [ipaddress.ip_network(c, strict=False) for c in (cidrs or [])]

    def domain_ok(self, d: str) -> bool:
        d = d.lower()
        return not any(d == a or d.endswith("." + a) for a in self.domains)

    def ip_ok(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self.permit_test and any(a in n for n in self.TEST_NETS):
            return True
        if a.is_private or a.is_loopback or a.is_multicast or a.is_reserved or a.is_link_local or a.is_unspecified:
            return False
        return not any(a in n for n in self.nets)


def _valid_domain(d: str) -> bool:
    parts = d.lower().split(".")
    tld = parts[-1]
    return len(parts) >= 2 and tld in TLDS and tld not in FILE_EXT_NOT_TLD


def classify(value: str) -> str | None:
    v = value.strip()
    if RE_URL.fullmatch(v):
        return "url"
    if RE_IPV4.fullmatch(v):
        return "ipv4"
    if re.fullmatch(r"[0-9.]+:\d+", v):
        return "ipv4"
    if RE_SHA256.fullmatch(v):
        return "sha256"
    if RE_SHA1.fullmatch(v):
        return "sha1"
    if RE_MD5.fullmatch(v):
        return "md5"
    if RE_EMAIL.fullmatch(v):
        return "email"
    if RE_DOMAIN.fullmatch(v) and _valid_domain(v):
        return "domain"
    return None


def extract(text: str, allow: Allowlist | None = None) -> dict[str, set[str]]:
    """Extract IOCs from free text. Returns {type: {values}}."""
    allow = allow or Allowlist()
    t = refang(text or "")
    out: dict[str, set[str]] = {k: set() for k in ("url", "ipv4", "domain", "sha256", "sha1", "md5", "email", "cve")}

    for u in RE_URL.findall(t):
        u = u.rstrip(".,;:")
        host = urlparse(u).hostname or ""
        if (RE_IPV4.fullmatch(host) and allow.ip_ok(host)) or (host and _valid_domain(host) and allow.domain_ok(host)):
            out["url"].add(u)
    stripped = RE_URL.sub(" ", t)  # avoid double-counting URL hosts as domains
    for h in RE_SHA256.findall(stripped):
        out["sha256"].add(h.lower())
    s2 = RE_SHA256.sub(" ", stripped)
    for h in RE_SHA1.findall(s2):
        out["sha1"].add(h.lower())
    s3 = RE_SHA1.sub(" ", s2)
    for h in RE_MD5.findall(s3):
        out["md5"].add(h.lower())
    for ip in RE_IPV4.findall(stripped):
        if allow.ip_ok(ip):
            out["ipv4"].add(ip)
    for e in RE_EMAIL.findall(stripped):
        if allow.domain_ok(e.split("@")[1]):
            out["email"].add(e.lower())
    no_email = RE_EMAIL.sub(" ", stripped)
    for d in RE_DOMAIN.findall(no_email):
        d = d.lower().rstrip(".")
        if _valid_domain(d) and allow.domain_ok(d) and not RE_IPV4.fullmatch(d):
            out["domain"].add(d)
    for c in RE_CVE.findall(t):
        out["cve"].add(c.upper())
    return out
