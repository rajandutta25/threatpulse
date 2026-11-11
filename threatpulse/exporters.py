"""Export formats: STIX 2.1, CSV, plain-text EDL blocklists, Suricata ruleset."""
from __future__ import annotations

import csv
import io
import json
import uuid
from urllib.parse import urlparse

from .db import now
from . import detections

NS = uuid.UUID("6f1c2d6e-3f6a-4b5e-9d1a-7c1e2b3a4d5f")
IDENTITY_ID = f"identity--{uuid.uuid5(NS, 'threatpulse')}"
HASH_KEY = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(t: str, v: str) -> str | None:
    if t == "ipv4":
        return f"[ipv4-addr:value = '{_esc(v)}']"
    if t == "domain":
        return f"[domain-name:value = '{_esc(v)}']"
    if t == "url":
        return f"[url:value = '{_esc(v)}']"
    if t == "email":
        return f"[email-addr:value = '{_esc(v)}']"
    if t in HASH_KEY:
        return f"[file:hashes.'{HASH_KEY[t]}' = '{_esc(v)}']"
    return None


def stix_bundle(indicators: list[dict], advisories: list[dict] | None = None,
                links: dict[str, list[str]] | None = None, vulns: list[dict] | None = None) -> dict:
    ts = now().replace("Z", ".000Z")
    objs = [{"type": "identity", "spec_version": "2.1", "id": IDENTITY_ID, "created": ts, "modified": ts,
             "name": "ThreatPulse", "identity_class": "system"}]
    ind_ids = {}
    for i in indicators:
        pat = stix_pattern(i["type"], i["value"])
        if not pat:
            continue
        sid = f"indicator--{uuid.uuid5(NS, i['id'])}"
        ind_ids[i["id"]] = sid
        first = (i.get("first_seen") or now()).replace("Z", ".000Z")
        o = {"type": "indicator", "spec_version": "2.1", "id": sid, "created": first, "modified": ts,
             "created_by_ref": IDENTITY_ID, "name": f"{i['type']}: {i['value']}", "pattern": pat,
             "pattern_type": "stix", "valid_from": first, "confidence": int(i.get("score") or i.get("confidence") or 50),
             "indicator_types": ["malicious-activity"],
             "labels": [x for x in [i.get("malware"), i.get("threat_type")] + (i.get("tags") or []) if x][:10],
             "external_references": [{"source_name": s, "description": f"Reported by {s}"} for s in i.get("sources", [])]}
        if i.get("reference"):
            o["external_references"].append({"source_name": "reference", "url": i["reference"]})
        objs.append(o)
    vuln_ids = {}
    for v in vulns or []:
        vid = f"vulnerability--{uuid.uuid5(NS, v['cve'])}"
        vuln_ids[v["cve"]] = vid
        objs.append({"type": "vulnerability", "spec_version": "2.1", "id": vid, "created": ts, "modified": ts,
                     "name": v["cve"], "description": v.get("description") or "",
                     "external_references": [{"source_name": "cve", "external_id": v["cve"]}]})
    for a in advisories or []:
        refs = [ind_ids[x] for x in (links or {}).get(a["id"], []) if x in ind_ids]
        refs += [vuln_ids[c] for c in a.get("cves", []) if c in vuln_ids]
        objs.append({"type": "report", "spec_version": "2.1", "id": f"report--{uuid.uuid5(NS, a['id'])}",
                     "created": ts, "modified": ts, "created_by_ref": IDENTITY_ID, "name": a["title"],
                     "description": a.get("summary", ""), "published": a["published"].replace("Z", ".000Z"),
                     "report_types": ["threat-report"], "object_refs": refs or [IDENTITY_ID],
                     "labels": a.get("tags", [])[:10],
                     "external_references": [{"source_name": a["source"], **({"url": a["url"]} if a.get("url") else
                                                                       {"description": a["source"]})}]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def to_csv(indicators: list[dict]) -> str:
    buf = io.StringIO()
    cols = ["type", "value", "score", "confidence", "malware", "threat_type", "sources", "first_seen", "last_seen",
            "reference"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for i in indicators:
        w.writerow({**i, "sources": ";".join(i.get("sources", []))})
    return buf.getvalue()


def to_edl(indicators: list[dict], ioc_type: str) -> str:
    """Plain list for PAN-OS / FortiGate / Check Point external dynamic lists."""
    out = []
    for i in indicators:
        if i["type"] != ioc_type:
            continue
        v = i["value"]
        if ioc_type == "url":  # PAN-OS URL EDLs exclude the scheme
            p = urlparse(v)
            v = (p.netloc + p.path)[:255]
        out.append(v)
    return "\n".join(sorted(set(out))) + ("\n" if out else "")


def to_suricata(indicators: list[dict]) -> str:
    header = f"# ThreatPulse Suricata ruleset — generated {now()}\n"
    return header + detections.suricata(detections._split(indicators), "ThreatPulse feed") + "\n"


def dumps(o) -> str:
    return json.dumps(o, indent=2)
