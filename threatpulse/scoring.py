"""Risk scoring for vulnerabilities, indicators and advisories (0-100)."""
from __future__ import annotations

from datetime import datetime, timezone

SEV_BASE = {"critical": 70, "high": 55, "medium": 35, "low": 20}


def _age_days(iso: str | None) -> float:
    if not iso:
        return 999
    try:
        d = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - d).total_seconds() / 86400
    except ValueError:
        return 999


def vuln_risk(v: dict) -> float:
    """CVSS (impact) + EPSS (likelihood) + KEV (confirmed exploitation) + ransomware use."""
    cvss = v.get("cvss") if v.get("cvss") is not None else 6.0
    r = cvss * 4 + (v.get("epss") or 0) * 30 + (20 if v.get("kev") else 0) + (10 if v.get("ransomware") else 0)
    return round(min(r, 100), 1)


def indicator_score(i: dict) -> float:
    corroboration = min(len(i.get("sources") or []) - 1, 3) * 10
    age = _age_days(i.get("last_seen"))
    fresh = 20 if age < 2 else 10 if age < 7 else 0 if age < 30 else -15
    return round(max(0, min(100, (i.get("confidence") or 50) * 0.7 + corroboration + fresh)), 1)


def is_relevant(text: str, vendors: list[str], products: list[str], vulns: list[dict]) -> bool:
    import re
    # strip URLs/domains/emails so "microsoft.com" in an article doesn't flag Microsoft as affected
    low = re.sub(r"\S+@\S+|\bhttps?://\S+|\b[\w-]+\.(?:com|net|org|io|gov)\b", " ", text.lower())
    hay = low + " " + " ".join(f"{v.get('vendor') or ''} {v.get('product') or ''}".lower() for v in vulns)
    return any(w and re.search(rf"\b{re.escape(w)}\b", hay) for w in vendors + products)


def advisory_score(adv: dict, vulns: list[dict], n_indicators: int, relevant: bool) -> float:
    s = SEV_BASE.get(adv.get("severity", "medium"), 35)
    if vulns:
        s += max(vuln_risk(v) for v in vulns) * 0.3
    s += min(n_indicators, 50) / 50 * 10
    s += 15 if relevant else 0
    age = _age_days(adv.get("published"))
    s += 5 if age < 1 else 3 if age < 3 else 0
    return round(min(s, 100), 1)
