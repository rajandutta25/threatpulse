"""Generates ready-to-run hunting queries and detection rules from a set of indicators.

Platforms: Splunk SPL, Microsoft Defender XDR / Sentinel KQL, Google SecOps (Chronicle) YARA-L 2.0,
Suricata, and Sigma.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from urllib.parse import urlparse

MAX = 200  # values per query; larger sets should go to a lookup / reference list


def _split(indicators: list[dict]) -> dict[str, list[str]]:
    out = {"ipv4": [], "domain": [], "url": [], "sha256": [], "sha1": [], "md5": [], "email": []}
    for i in sorted(indicators, key=lambda x: -(x.get("score") or 0)):
        if i["type"] in out and len(out[i["type"]]) < MAX:
            out[i["type"]].append(i["value"])
    return out


def _q(vals, quote='"'):
    return ", ".join(f'{quote}{v.replace(chr(92), chr(92) * 2).replace(quote, chr(92) + quote)}{quote}' for v in vals)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")[:50] or "advisory"


def _sid(s: str) -> int:
    return 9_000_000 + int(hashlib.md5(s.encode()).hexdigest(), 16) % 999_999


def splunk(v: dict) -> str:
    parts = []
    if v["ipv4"]:
        parts.append(f"dest_ip IN ({_q(v['ipv4'])}) OR src_ip IN ({_q(v['ipv4'])})")
    if v["domain"]:
        parts.append(f"query IN ({_q(v['domain'])}) OR dest IN ({_q(v['domain'])}) "
                     f"OR url_domain IN ({_q(v['domain'])})")
    if v["url"]:
        parts.append(f"url IN ({_q(v['url'])})")
    hashes = v["sha256"] + v["sha1"] + v["md5"]
    if hashes:
        parts.append(f"file_hash IN ({_q(hashes)}) OR sha256 IN ({_q(v['sha256'] or ['-'])})")
    if v["email"]:
        parts.append(f"src_user IN ({_q(v['email'])}) OR sender IN ({_q(v['email'])})")
    if not parts:
        return ""
    return ("index=* earliest=-30d (" + " OR ".join(f"({p})" for p in parts) + ")\n"
            "| stats count min(_time) as first_seen max(_time) as last_seen values(sourcetype) as sourcetypes "
            "by src_ip dest_ip dest query url file_hash user\n| convert ctime(first_seen) ctime(last_seen)")


def kql(v: dict) -> str:
    lets, unions = [], []
    if v["ipv4"]:
        lets.append(f"let tp_ips = dynamic([{_q(v['ipv4'])}]);")
    if v["domain"]:
        lets.append(f"let tp_domains = dynamic([{_q(v['domain'])}]);")
    if v["url"]:
        lets.append(f"let tp_urls = dynamic([{_q(v['url'])}]);")
    hashes = v["sha256"] + v["sha1"] + v["md5"]
    if hashes:
        lets.append(f"let tp_hashes = dynamic([{_q(hashes)}]);")
    net_conds = []
    if v["ipv4"]:
        net_conds.append("RemoteIP in (tp_ips)")
    if v["domain"]:
        net_conds.append("RemoteUrl has_any (tp_domains)")
    if v["url"]:
        net_conds.append("RemoteUrl in (tp_urls)")
    if net_conds:
        unions.append(f"(DeviceNetworkEvents | where Timestamp > ago(30d) | where {' or '.join(net_conds)})")
    if hashes:
        cond = "SHA256 in (tp_hashes) or SHA1 in (tp_hashes) or MD5 in (tp_hashes)"
        unions.append(f"(DeviceFileEvents | where Timestamp > ago(30d) | where {cond})")
        unions.append(f"(DeviceProcessEvents | where Timestamp > ago(30d) | where {cond})")
    if v["email"]:
        lets.append(f"let tp_senders = dynamic([{_q(v['email'])}]);")
        unions.append("(EmailEvents | where Timestamp > ago(30d) | where SenderFromAddress in (tp_senders))")
    if not unions:
        return ""
    return ("// Microsoft Defender XDR advanced hunting (also works in Sentinel with MDE connector)\n" +
            "\n".join(lets) + "\nunion " + ",\n      ".join(unions) +
            "\n| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl, FileName, SHA256, "
            "InitiatingProcessFileName, SenderFromAddress\n| sort by Timestamp desc")


def yaral(v: dict, name: str, severity: str = "HIGH") -> str:
    conds = []
    conds += [f'$e.target.ip = "{x}"' for x in v["ipv4"]]
    conds += [f'$e.network.dns.questions.name = "{x}" nocase' for x in v["domain"]]
    conds += [f'$e.target.hostname = "{x}" nocase' for x in v["domain"]]
    conds += [f'$e.target.url = "{x}"' for x in v["url"]]
    conds += [f'$e.target.file.sha256 = "{x}" nocase' for x in v["sha256"]]
    conds += [f'$e.target.file.sha1 = "{x}" nocase' for x in v["sha1"]]
    conds += [f'$e.target.file.md5 = "{x}" nocase' for x in v["md5"]]
    conds += [f'$e.network.email.from = "{x}" nocase' for x in v["email"]]
    if not conds:
        return ""
    body = "\n      or ".join(conds)
    return f"""// Google SecOps (Chronicle) YARA-L 2.0. For large sets, load values into a reference
// list (e.g. %tp_block_ips) and use: $e.target.ip in %tp_block_ips
rule tp_{_slug(name)} {{
  meta:
    author = "ThreatPulse"
    description = "IOC match: {name.replace('"', "'")[:120]}"
    severity = "{severity.upper()}"
    priority = "{severity.upper()}"
  events:
    (
      {body}
    )
  outcome:
    $risk_score = 80
  condition:
    $e
}}"""


def suricata(v: dict, name: str) -> str:
    rules, n = [], name.replace('"', "'").replace(";", ",")[:80]
    ips = v["ipv4"]
    for i in range(0, len(ips), 50):
        chunk = ips[i:i + 50]
        rules.append(f'alert ip $HOME_NET any -> [{",".join(chunk)}] any (msg:"ThreatPulse IOC IP - {n}"; '
                     f'classtype:trojan-activity; sid:{_sid(n + "ip" + str(i))}; rev:1;)')
    for d in v["domain"]:
        rules.append(f'alert dns $HOME_NET any -> any any (msg:"ThreatPulse DNS query {d} - {n}"; '
                     f'dns.query; content:"{d}"; nocase; endswith; classtype:trojan-activity; '
                     f'sid:{_sid(n + d)}; rev:1;)')
        rules.append(f'alert tls $HOME_NET any -> any any (msg:"ThreatPulse TLS SNI {d} - {n}"; '
                     f'tls.sni; content:"{d}"; nocase; endswith; classtype:trojan-activity; '
                     f'sid:{_sid(n + d + "sni")}; rev:1;)')
    for u in v["url"][:100]:
        p = urlparse(u)
        if p.scheme == "http" and p.hostname and p.path:
            path = (p.path + (("?" + p.query) if p.query else "")).replace('"', "%22").replace(";", "%3B")
            rules.append(f'alert http $HOME_NET any -> any any (msg:"ThreatPulse URL {p.hostname} - {n}"; '
                         f'http.host; content:"{p.hostname}"; nocase; http.uri; content:"{path[:200]}"; '
                         f'classtype:trojan-activity; sid:{_sid(n + u)}; rev:1;)')
    return "\n".join(rules)


def sigma(v: dict, name: str) -> str:
    docs = []
    rid = lambda s: str(uuid.uuid5(uuid.NAMESPACE_URL, "threatpulse:" + name + s))  # noqa: E731
    if v["domain"]:
        vals = "\n".join(f"            - '{d}'" for d in v["domain"])
        docs.append(f"""title: ThreatPulse - DNS query to IOC domain ({name[:60]})
id: {rid('dns')}
status: experimental
description: DNS query to a domain associated with "{name[:100]}"
author: ThreatPulse
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
{vals}
    condition: selection
falsepositives:
    - Shared hosting / sinkholed domains
level: high""")
    hashes = v["sha256"] + v["sha1"] + v["md5"]
    if hashes:
        vals = "\n".join(f"            - '{h}'" for h in hashes)
        docs.append(f"""title: ThreatPulse - Process with IOC hash ({name[:60]})
id: {rid('hash')}
status: experimental
description: Process image hash associated with "{name[:100]}"
author: ThreatPulse
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Hashes|contains:
{vals}
    condition: selection
falsepositives:
    - Unlikely
level: critical""")
    return "\n---\n".join(docs)


def generate(indicators: list[dict], name: str, severity: str = "high") -> dict[str, str]:
    v = _split(indicators)
    return {"splunk": splunk(v), "kql": kql(v), "chronicle_yaral": yaral(v, name, severity),
            "suricata": suricata(v, name), "sigma": sigma(v, name)}
