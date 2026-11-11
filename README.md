# ThreatPulse

**ThreatPulse is an open-source threat intelligence platform you host yourself.** It collects the latest attacks, exploited vulnerabilities and IOCs from free government, vendor and community feeds. It ranks them by risk to *your* environment and turns each advisory into a prioritized action list with ready-to-deploy detections.

```
 Feeds ──► Normalize & extract IOCs ──► Enrich (NVD, EPSS, KEV) ──► Correlate ──► Score ──► Actions + Detections ──► API / UI / Exports / Alerts
```

## What you get for each advisory

| | |
|---|---|
| **Risk score (0–100)** | Combines severity, CVSS, EPSS exploit probability, CISA KEV status, ransomware use, IOC volume, recency and **whether it affects your watchlisted stack** |
| **Action plan** | P1–P4 tasks (Triage, Patch, Hunt, Block, Detect, Harden), each with an owner team and a due date. KEV deadlines are honoured and tighter SLAs apply when it hits your stack. |
| **IOCs** | Deduplicated across sources, corroboration-scored, defang-aware, with false-positive filtering (private IPs, allowlisted domains, filenames that look like domains) |
| **Detections** | Generated per advisory: **Splunk SPL**, **Defender XDR / Sentinel KQL**, **Google SecOps YARA-L 2.0**, **Suricata**, **Sigma** |
| **Exports** | STIX 2.1 (validated), EDL blocklists for PAN-OS / FortiGate / Check Point, Suricata ruleset, CSV, REST API |

## Sources

| Source | What it adds | Key |
|---|---|---|
| CISA KEV | Actively exploited CVEs, required action, due date, ransomware use | none |
| NVD CVE API 2.0 | CVSS + description | optional (faster) |
| FIRST EPSS | Exploitation probability for the next 30 days | none |
| abuse.ch Feodo Tracker | Botnet C2 IPs | none |
| abuse.ch ThreatFox | Malware-family-tagged IOCs | free Auth-Key |
| abuse.ch URLhaus | Live malware distribution URLs | free Auth-Key |
| AlienVault OTX | Campaign pulses with IOCs, actors, ATT&CK IDs | free |
| RSS: CISA, Unit 42, Talos, DFIR Report, SANS ISC, MSFT, BleepingComputer, THN | Latest attacks and advisories; IOCs + CVEs extracted from the text (full article for selected feeds) | none |

**Correlation:** if an advisory mentions a malware family (e.g. "LummaStealer"), ThreatPulse automatically links the fresh ThreatFox, Feodo and URLhaus IOCs for that family. A news article then comes with current, blockable infrastructure, not only the IOCs printed in the article.

## Quick start

```bash
pip install -r requirements.txt
cp config.example.toml config.toml        # edit [watchlist] with your vendors/products
cp .env.example .env && set -a && . ./.env && set +a

python -m threatpulse demo                # optional: load clearly-labelled SAMPLE data offline
python -m threatpulse collect             # pull live feeds (KEV, RSS, Feodo work with no keys)
python -m threatpulse top -n 10           # top advisories + actions in the terminal
python -m threatpulse serve               # dashboard at http://localhost:8080, API docs at /docs
```

Docker:

```bash
cp config.example.toml config.toml && cp .env.example .env
docker compose up -d --build              # auto-refreshes every TP_REFRESH_MINUTES
```

Or schedule with cron: `0 * * * * cd /opt/threatpulse && python -m threatpulse collect`.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/advisories?q=&min_score=&days=&relevant=true` | Ranked advisories |
| `GET /api/advisories/{id}` | Advisory + CVEs + IOCs + actions + detections |
| `GET /api/advisories/{id}/stix` | STIX 2.1 bundle for one advisory |
| `GET /api/indicators?type=&malware=&min_score=` | IOC search |
| `GET /api/vulns?kev=true` | Exploited CVEs ranked by risk |
| `GET /api/lookup?value=` | Is this IP/domain/hash/URL/CVE known? (accepts defanged input) |
| `GET /api/export/edl/{ipv4,domain,url,sha256}` | Plain-text EDL for firewalls/proxies/DNS |
| `GET /api/export/stix` · `/csv` · `/suricata` | Bulk exports |
| `POST /api/refresh` | Trigger collection |

**Firewall integration:** point a PAN-OS External Dynamic List or a FortiGate external threat feed at
`http://<host>:8080/api/export/edl/ipv4?min_score=70`. Use the `domain` and `url` lists for DNS security and the proxy.

## Scoring

- **Vulnerability risk:** `CVSS×4 + EPSS×30 + 20 if KEV + 10 if ransomware` (capped at 100)
- **Indicator score:** `source confidence×0.7 + 10 per corroborating source + freshness bonus` (aged IOCs decay)
- **Advisory score:** `severity base + 0.3×max vuln risk + IOC volume + 15 if it hits your stack + recency`

The weights are in `threatpulse/scoring.py`. Tune them to your risk appetite.

## Extending

- **New feed:** subclass `Collector` in `collectors.py`, return a `Batch`, and add it to `FEED_COLLECTORS`.
- **New detection platform:** add a function to `detections.py` and register it in `generate()`.
- **New action rule:** add it to `playbook.py`.
- **Roadmap ideas:** TAXII 2.1 server, MISP push, an LLM summariser for long reports, ATT&CK Navigator layer export, asset-inventory matching by CPE, PostgreSQL backend.

## Testing

```bash
pip install -r requirements-dev.txt && pytest -q
```

The test fixtures use only fictitious data: `CVE-2099-*`, RFC 5737 documentation IPs and the reserved `.test` TLD.

## Operational notes

- Review IOCs before auto-blocking them. Shared hosting and CDN IPs cause false positives, so start EDLs at `min_score=70` and add your own CDNs to `[allowlist]`.
- Respect each source's terms of use. Some abuse.ch and OTX data has commercial-use conditions.
- Without a key, NVD rate-limits to 5 requests per 30 s. ThreatPulse throttles automatically; adding a key makes enrichment roughly 10× faster.

License: Apache-2.0
