"""Turns an advisory + its CVEs + IOCs into a prioritized, owner-ready action list."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

NET = {"ipv4", "domain", "url"}
FILE = {"sha256", "sha1", "md5"}


def _due(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d")


def build_actions(adv: dict, vulns: list[dict], indicators: list[dict], relevant: bool) -> list[dict]:
    acts: list[dict] = []
    text = f"{adv.get('title', '')} {adv.get('summary', '')}".lower()
    tags = [t.lower() for t in adv.get("tags", [])]

    def add(priority, category, action, detail="", due=None, owner="SOC"):
        acts.append({"priority": priority, "category": category, "action": action, "detail": detail,
                     "due": due, "owner": owner})

    if relevant:
        add("P1", "Triage", "Confirm exposure: this advisory matches your watchlisted technology",
            "Identify affected assets in CMDB / EASM; record versions and internet exposure.", _due(1), "Vuln Mgmt")

    for v in sorted(vulns, key=lambda x: -(x.get("risk") or 0)):
        prod = " ".join(p for p in (v.get("vendor"), v.get("product")) if p) or "affected product"
        epss = v.get("epss") or 0
        if v.get("kev"):
            p, due = "P1", _due(3 if relevant else 7)
            if v.get("kev_due") and v["kev_due"] < due:
                due = v["kev_due"]
            add(p, "Patch", f"Patch {v['cve']} on {prod} (known exploited)",
                v.get("kev_action") or "Apply vendor updates or mitigations; discontinue use if unavailable.",
                due, "Infra / App owners")
            add("P1", "Hunt", f"Hunt for prior exploitation of {v['cve']}",
                f"Review logs of internet-facing {prod} for the last 30 days (since before disclosure): unusual "
                "requests, new admin accounts, webshells, unexpected child processes, outbound connections.",
                _due(2))
        elif epss >= 0.1 or (v.get("cvss") or 0) >= 9:
            add("P2", "Patch", f"Patch {v['cve']} on {prod}",
                f"CVSS {v.get('cvss') or 'n/a'}, EPSS {epss:.1%} — high likelihood/impact.", _due(14),
                "Infra / App owners")
        elif v.get("cvss") is not None:
            add("P3", "Patch", f"Schedule patch for {v['cve']} on {prod}",
                f"CVSS {v.get('cvss')}, EPSS {epss:.1%}.", _due(30), "Infra / App owners")

    net = [i for i in indicators if i["type"] in NET]
    files = [i for i in indicators if i["type"] in FILE]
    emails = [i for i in indicators if i["type"] == "email"]
    if net:
        add("P1" if adv.get("severity") in ("critical", "high") else "P2", "Block",
            f"Block {len(net)} network IOCs (IP/domain/URL)",
            "Push via EDL to firewall (/api/export/edl/<type>), DNS sinkhole/RPZ, and secure web proxy. "
            "Check for business-critical shared hosting before blocking IPs.", _due(1), "Network Security")
    if files:
        add("P1", "Block", f"Add {len(files)} file hashes to EDR block list",
            "Defender XDR custom indicators / CrowdStrike IOC management / SentinelOne blacklist.", _due(1), "EDR team")
    if net or files:
        add("P2", "Hunt", f"Retro-hunt {len(net) + len(files)} IOCs across 30 days of telemetry",
            "Use the generated Splunk / KQL / Chronicle YARA-L queries in the Detections tab.", _due(2))
        add("P2", "Detect", "Deploy generated detections to SIEM/IDS",
            "Suricata rules for NSM, Sigma for SIEM conversion, YARA-L for Google SecOps.", _due(3), "Detection Eng")
    if emails or "phish" in text:
        add("P2", "Hunt", "Search mail gateway for related phishing and purge",
            "Search sender addresses, subjects and URLs; soft-delete matches; notify affected users.", _due(1),
            "Email Security")

    for fam in adv.get("malware", [])[:5]:
        add("P2", "Detect", f"Validate EDR/AV coverage for {fam}",
            "Confirm vendor signature/behavioural coverage; run an emulation (e.g. Atomic Red Team) if available.",
            _due(5), "Detection Eng")

    techniques = sorted({t.split(":", 1)[1] for t in tags if t.startswith("attack:")} |
                        {m.upper() for m in re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", text, re.I)})
    if techniques:
        add("P3", "Detect", f"Review detection coverage for ATT&CK {', '.join(techniques[:8])}",
            "Map to existing rules in your SIEM; open detection backlog items for gaps.", _due(14), "Detection Eng")

    if "ransomware" in tags or "ransomware" in text:
        add("P2", "Harden", "Verify immutable/offline backups and run a restore test",
            "Also confirm MFA on remote access/VPN and restrict RDP/SMB exposure.", _due(7), "IT Ops")
    if re.search(r"\b(vpn|firewall|gateway|edge device|citrix|fortigate|ivanti|pan-os|asa|big-ip)\b", text):
        add("P2", "Harden", "Review edge-device exposure and admin interfaces",
            "Ensure management interfaces are not internet-facing; rotate credentials and session tokens after patching.",
            _due(7), "Network Security")

    if not acts:
        add("P4", "Awareness", "Review for situational awareness", "No direct indicators or CVEs extracted.", None)
    order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    return sorted(acts, key=lambda a: order[a["priority"]])
