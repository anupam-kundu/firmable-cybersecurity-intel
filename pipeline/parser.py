import gzip
import json
import os
from pipeline.resolver import HIGH_RISK_PORTS, resolve_company_domain, clean_org_name, classify_hosting

DEFAULT_DATA_PATH = (
    "data/raw/real_sample_100k.jsonl.gz"
    if os.path.exists("data/raw/real_sample_100k.jsonl.gz")
    else "data/sample/sample_2k.jsonl.gz"
)

def parse_and_aggregate(data_path: str = DEFAULT_DATA_PATH):
    companies = {}
    total_rows, resolved_rows = 0, 0

    with gzip.open(data_path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            total_rows += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            domain, res_source = resolve_company_domain(rec)
            if not domain:
                continue

            resolved_rows += 1
            ip_str = rec.get("ip_str", "")
            port = int(rec.get("port") or 0)
            product = (rec.get("product") or "").strip()[:120]
            version = (rec.get("version") or "").strip()[:60]
            asn = (rec.get("asn") or "").strip()
            isp = (rec.get("isp") or "").strip()
            loc = rec.get("location") or {}
            country_code = (loc.get("country_code") or "UNK")[:8]
            city = (loc.get("city") or "")[:100]

            cert = ((rec.get("ssl") or {}).get("cert") or {})
            ssl_expired = bool(cert.get("expired", False))
            issuer = cert.get("issuer") or {}
            ssl_issuer = str(issuer.get("O") or issuer.get("CN") or "")[:120]
            http_title = str((rec.get("http") or {}).get("title") or "").strip().replace("\n", " ")[:180]

            vulns = rec.get("vulns") or {}
            vuln_ids = list(vulns.keys()) if isinstance(vulns, dict) else []
            max_cvss = max((float(v.get("cvss") or 0) for v in vulns.values() if isinstance(v, dict)), default=0.0)
            tags = [str(t) for t in (rec.get("tags") or [])][:15]
            banner = str(rec.get("data") or "").strip()[:260]

            if domain not in companies:
                companies[domain] = {
                    "domain": domain, "company_name": clean_org_name(rec, domain),
                    "resolution_source": res_source, "country_code": country_code, "city": city,
                    "primary_asn": asn, "hosting_provider": classify_hosting(asn, isp, rec.get("org") or ""),
                    "ports": set(), "tech_stack": set(), "cves": set(), "max_cvss": 0.0,
                    "expired_ssl_count": 0, "high_risk_ports": set(), "tags": set(), "assets": {},
                }

            c = companies[domain]
            if c["country_code"] == "UNK" and country_code != "UNK":
                c["country_code"] = country_code
            if not c["city"] and city:
                c["city"] = city
            if port:
                c["ports"].add(port)
                if port in HIGH_RISK_PORTS:
                    c["high_risk_ports"].add(port)
            if product:
                c["tech_stack"].add(product)
            c["cves"].update(vuln_ids)
            c["max_cvss"] = max(c["max_cvss"], max_cvss)
            if ssl_expired:
                c["expired_ssl_count"] += 1
            c["tags"].update(tags)

            if (ip_str, port) not in c["assets"]:
                c["assets"][(ip_str, port)] = (
                    ip_str, port, rec.get("transport", "tcp"), product, version, asn, isp,
                    country_code, ssl_expired, ssl_issuer, http_title, vuln_ids[:20], tags, banner
                )

    print(f"Processed {total_rows:,} banners from {data_path} -> Resolved {resolved_rows:,} banners across {len(companies):,} unique B2B domains.")
    return companies
