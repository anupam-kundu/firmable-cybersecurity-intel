# Intelligence Design, Evaluation & 10 TB/Month Scaling Architecture

## 1. Hidden B2B Buying Signals Extracted from Shodan Telemetry

Raw Shodan banners are IP-centric and noisy. This pipeline translates low-level network telemetry into five confidence-scored commercial signals for cybersecurity sales teams:

| Signal Type | Raw Shodan Indicators | Commercial Buying Intent & Sales Angle | Confidence |
| :--- | :--- | :--- | :---: |
| **Active CVE Exposure** | `vulns` CVE keys + `cvss` severity (`max_cvss >= 9.0` flagged Critical) | Unpatched public infrastructure; urgent trigger for vulnerability management and automated patching tools. | **0.94** |
| **High-Risk Service / DB Exposure** | 16 weighted risky ports (`2375` Docker API, `9200` Elastic, `27017` MongoDB, `6379` Redis, `3389` RDP, `445` SMB, SQL/Postgres) | Shadow IT or misconfigured firewalls exposing internal datastores/admin UIs; ideal for Zero-Trust and CSPM. | **0.91** |
| **SSL/TLS Certificate Hygiene Failure** | `ssl.cert.expired == True` + `ssl.cert.issuer` | Lapsed certificate rotation indicating stretched SecOps teams; strong wedge for Certificate Lifecycle Management (CLM). | **0.96** |
| **Attack Surface Sprawl & Shadow Cloud** | Multi-endpoint `asset_count`, `tags` (`self-signed`, `database`, `ics`), and cloud ASN classification | Unmonitored multi-cloud expansion where External Attack Surface Management (EASM) visibility is missing. | **0.90** |
| **Verified Edge Footprint** | `product`, `version`, `http.title`, and `hosting_provider` | ICP qualification and competitive displacement telemetry even when zero active vulnerabilities are present. | **0.85** |

---

## 2. Entity Resolution & Exposure Scoring (`0–100`)

* **3-Tier Domain Waterfall (`pipeline/resolver.py`):** Resolves corporate root domains in priority order from `domains` (`shodan_domains`) -> `ssl.cert.subject.CN` (`ssl_cert_cn`) -> `hostnames` (`ptr_hostname`).
* **Public Suffix & Blocklist Hygiene:** Uses Mozilla's Public Suffix List (`tldextract`) for accurate multi-part ccTLD extraction (e.g., `.co.in`, `.com.au`, `.co.uk`) and an externalized `config/infra_blocklist.txt` to exclude hyperscalers, CDNs, and telco PTR noise without code changes.
* **Weighted Exposure Score (`0–100`):** Combines CVE burden (up to `+35`), critical exposed ports (up to `+25`), expired TLS certificates (`+8` each, up to `+15`), multi-asset sprawl (`+3` per extra endpoint, up to `+10`), and high-risk tags (`+8`) into four sales tiers (**Critical >= 75**, **High >= 50**, **Medium >= 30**, **Low < 30**).

---

## 3. Scaling to 1,000 Files / Month (~10 TB Compressed / ~30B Banners)

| Layer | Current Implementation | 10 TB/Month Production Architecture |
| :--- | :--- | :--- |
| **Trigger & Idempotency** | CLI ingestion with SHA-256 `processed_files` ledger | **Object Storage Events (B2/S3) -> Queue (SQS/PubSub) -> Autoscaling Workers** deduplicated via `processed_files` checksums. |
| **Out-of-Core Parsing** | Line-by-line `gzip.open` streaming | **Parallel Chunked Workers using DuckDB / Polars** (`scan_ndjson`) to pre-aggregate `(domain, ip_str, port)` per 10 GB file in ~3 minutes without OOM. |
| **Incremental Database Writes** | Transactional `UPSERT` (`ON CONFLICT`) across `companies`, `exposed_assets`, and `cyber_signals` | **Unlogged Staging Tables + Batched `MERGE` / `UPSERT`** so incoming daily/monthly files enrich existing company profiles with zero downtime. |
| **Hot / Cold Storage Split** | Normalized PostgreSQL tables | **PostgreSQL Hot Store** (~5–20M resolved B2B companies + active signals, <30 GB, <15ms UI queries) + **Iceberg / ClickHouse Cold Lake** for raw historical banners. |
| **Temporal Delta Signals** | `first_seen_at` / `last_seen_at` timestamps on endpoints | **Change-Detection Alerts** comparing new scan state against prior company state (e.g., *"New RDP port 3389 exposed in last 24h"*). |

---

## 4. Measuring Quality & LLM Cost Discipline

* **Zero Per-Banner LLM Cost:** Entity resolution, risk scoring, and signal synthesis are 100% deterministic Python—processing 30B banners/month costs **$0 in LLM API fees** with zero hallucinated CVEs or ports. Optional LLM usage is strictly restricted to on-demand rep click actions for Critical accounts.
* **Evaluation Loop:**
  1. *Entity Resolution Precision:* Audit random samples of 200 resolved domains per batch to verify `<1%` ISP/CDN false-positive leakage into `companies`.
  2. *Idempotency & Rollup Integrity:* Re-ingesting the same `.jsonl.gz` archive skips duplicate work via `processed_files`, while ingesting a second archive merges endpoints without inflating `asset_count`.
