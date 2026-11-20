# Firmable B2B Cyber Threat & Attack Surface Intelligence Pipeline

End-to-end data engineering and B2B intelligence pipeline that transforms raw Shodan internet scan banners into **company-resolved attack surface profiles, exposure risk scores, and actionable GTM cyber signals** backed by PostgreSQL, FastAPI, and an interactive web explorer.

## Architecture Overview

```text
Shodan JSONL.GZ Stream (100K Real Banners / 2K Sample)
        │
        ▼
[1] Entity Resolution & Hygiene (pipeline/resolver.py + tldextract)
    • Extracts root B2B domains from DNS domains, SSL Cert CNs & PTR hostnames
    • Filters cloud/ISP noise via externalized config/infra_blocklist.txt
        │
        ▼
[2] Aggregation & Risk Scoring (pipeline/parser.py + load_db.py)
    • Deduplicates IP:Port assets, maps CVEs/CVSS, detects expired TLS & risky ports
    • Computes weighted 0–100 Exposure Score & generates confidence-scored GTM signals
        │
        ▼
[3] Relational Storage (PostgreSQL: companies, exposed_assets, cyber_signals)
        │
        ▼
[4] FastAPI REST Service + Executive Explorer (api/main.py + frontend/index.html)
```

## Key Engineering Highlights

- **Dynamic Domain Resolution (`tldextract` + `config/infra_blocklist.txt`):** Uses Mozilla's Public Suffix List for accurate multi-part ccTLD parsing (e.g., `.co.in`, `.com.au`, `.co.uk`) and an externalized infrastructure blocklist so analysts can exclude new ISP/CDN patterns without code changes.
- **Database Integrity:** Bulk-loads normalized company, endpoint, and signal records with `psycopg2.extras.execute_values` and NUL-byte (`\x00`) banner sanitization.
- **B2B Commercialization:** Translates raw technical telemetry (open databases, high-CVSS CVEs, expired SSL certificates) into plain-English GTM outreach recommendations.

## Quickstart

```bash
# 1. Setup virtual environment & install dependencies
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# 2. Initialize schema & ingest data (uses 100K raw dataset if present, else 2K repo sample)
PYTHONPATH=. python pipeline/load_db.py

# 3. Launch API & Interactive Dashboard
uvicorn api.main:app --reload --port 8000
```

Open **http://127.0.0.1:8000** in your browser (or **http://127.0.0** for OpenAPI Swagger docs).

## Deep-Dive Architecture & Scaling Plan

See [ARCHITECTURE.md](ARCHITECTURE.md) for the signal taxonomy, scoring weights, quality evaluation metrics, and 10 TB/month production scaling design.

## Hosted App

https://firmable-cybersecurity-intel.onrender.com/
