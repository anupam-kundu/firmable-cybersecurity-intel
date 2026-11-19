import hashlib
import json
import sys
import time
from psycopg2.extras import execute_values
from pipeline.db_schema import get_connection, init_schema, reset_schema
from pipeline.resolver import HIGH_RISK_PORTS, compute_risk_score
from pipeline.parser import DEFAULT_DATA_PATH, parse_and_aggregate

def clean(row):
    return tuple(v.replace("\x00", "") if isinstance(v, str) else v for v in row)

def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def load_to_postgres(data_path: str = DEFAULT_DATA_PATH, force: bool = False):
    init_schema()
    f_hash = file_sha256(data_path)
    conn = get_connection()

    with conn.cursor() as cur:
        cur.execute("SELECT processed_at FROM processed_files WHERE file_hash = %s", (f_hash,))
        row = cur.fetchone()
        if row and not force:
            ts = row
            print(f"Skipping {data_path} (already ingested at {ts}). Use --force to re-ingest.")
            conn.close()
            return

    companies = parse_and_aggregate(data_path)
    domains = sorted(companies.keys())
    if not domains:
        print("No corporate domains resolved in batch.")
        conn.close()
        return

    company_rows = [
        clean((
            companies[d]["domain"], companies[d]["company_name"], companies[d]["resolution_source"],
            companies[d]["country_code"], companies[d]["city"], companies[d]["primary_asn"],
            companies[d]["hosting_provider"], round(companies[d]["max_cvss"], 1)
        ))
        for d in domains
    ]

    with conn.cursor() as cur:
        inserted = execute_values(
            cur,
            """INSERT INTO companies (
                domain, company_name, resolution_source, country_code, city,
                primary_asn, hosting_provider, max_cvss
            ) VALUES %s
            ON CONFLICT (domain) DO UPDATE SET
                company_name = COALESCE(NULLIF(EXCLUDED.company_name, ''), companies.company_name),
                country_code = CASE WHEN companies.country_code = 'UNK' THEN EXCLUDED.country_code ELSE companies.country_code END,
                city = COALESCE(NULLIF(companies.city, ''), EXCLUDED.city),
                max_cvss = GREATEST(companies.max_cvss, EXCLUDED.max_cvss),
                updated_at = NOW()
            RETURNING id, domain""",
            company_rows, fetch=True
        )
        dom_id = {dom: cid for cid, dom in inserted}
        affected_ids = list(dom_id.values())

        asset_rows = [
            clean((dom_id[d], *a))
            for d in domains
            for a in companies[d]["assets"].values()
        ]
        execute_values(
            cur,
            """INSERT INTO exposed_assets (
                company_id, ip_str, port, transport, product, version, asn, isp,
                country_code, ssl_expired, ssl_issuer, http_title, vuln_ids, tags, banner_snippet
            ) VALUES %s
            ON CONFLICT (company_id, ip_str, port) DO UPDATE SET
                product = COALESCE(NULLIF(EXCLUDED.product, ''), exposed_assets.product),
                version = COALESCE(NULLIF(EXCLUDED.version, ''), exposed_assets.version),
                ssl_expired = EXCLUDED.ssl_expired,
                http_title = COALESCE(NULLIF(EXCLUDED.http_title, ''), exposed_assets.http_title),
                vuln_ids = ARRAY(SELECT DISTINCT unnest(exposed_assets.vuln_ids || EXCLUDED.vuln_ids)),
                tags = ARRAY(SELECT DISTINCT unnest(exposed_assets.tags || EXCLUDED.tags)),
                last_seen_at = NOW()""",
            asset_rows, page_size=2000
        )
        cur.execute("""
            SELECT company_id,
                   COUNT(*) AS asset_cnt,
                   ARRAY_AGG(DISTINCT port) AS ports,
                   ARRAY_AGG(DISTINCT product) FILTER (WHERE product <> '') AS stack,
                   ARRAY_AGG(DISTINCT v) FILTER (WHERE v IS NOT NULL) AS cves,
                   COUNT(*) FILTER (WHERE ssl_expired) AS exp_ssl,
                   ARRAY_AGG(DISTINCT t) FILTER (WHERE t IS NOT NULL) AS all_tags
            FROM exposed_assets
            LEFT JOIN LATERAL unnest(vuln_ids) AS v ON TRUE
            LEFT JOIN LATERAL unnest(tags) AS t ON TRUE
            WHERE company_id = ANY(%s)
            GROUP BY company_id
        """, (affected_ids,))
        rollups = {
            cid: (asset_cnt, ports, stack, cves, exp_ssl, all_tags)
            for cid, asset_cnt, ports, stack, cves, exp_ssl, all_tags in cur.fetchall()
        }

        cur.execute("SELECT id, max_cvss, hosting_provider FROM companies WHERE id = ANY(%s)", (affected_ids,))
        comp_meta = {cid: (float(cvss or 0), hosp) for cid, cvss, hosp in cur.fetchall()}

        update_rows, signal_rows = [], []
        for cid, (asset_cnt, ports, stack, cves, exp_ssl, all_tags) in rollups.items():
            ports_set = {p for p in (ports or []) if p}
            hr_ports = ports_set & set(HIGH_RISK_PORTS.keys())
            cves_list = sorted({c for c in (cves or []) if c}, reverse=True)
            stack_list = sorted({s for s in (stack or []) if s})[:20]
            tags_set = {t for t in (all_tags or []) if t}
            max_cvss, hosting = comp_meta[cid]

            score, tier = compute_risk_score(asset_cnt, len(cves_list), max_cvss, exp_ssl, hr_ports, tags_set)
            update_rows.append((
                cid, asset_cnt, sorted(ports_set)[:30], stack_list,
                len(cves_list), cves_list[:10], exp_ssl, len(hr_ports), score, tier
            ))

            if cves_list:
                sev = "Critical" if max_cvss >= 9.0 else "High"
                signal_rows.append(clean((
                    cid, "Active CVE Exposure", sev, 0.94,
                    f"{len(cves_list)} known CVEs detected (Max CVSS {max_cvss:.1f}: {', '.join(cves_list[:3])}).",
                    "Prioritize vulnerability remediation outreach; pitch automated attack-surface patching.",
                    json.dumps({"cve_count": len(cves_list), "max_cvss": max_cvss})
                )))
            if hr_ports:
                p_names = [f"{p} ({HIGH_RISK_PORTS[p]})" for p in sorted(hr_ports)]
                signal_rows.append(clean((
                    cid, "High-Risk Service / DB Exposure", "High", 0.91,
                    f"Publicly reachable sensitive services: {', '.join(p_names)}.",
                    "Alert security leadership regarding zero-trust segmentation and firewall hardening.",
                    json.dumps({"exposed_ports": sorted(hr_ports)})
                )))
            if exp_ssl > 0:
                signal_rows.append(clean((
                    cid, "SSL/TLS Certificate Hygiene Failure", "Medium", 0.96,
                    f"{exp_ssl} public endpoint(s) serving expired TLS certificates.",
                    "Engage DevOps/SecOps team with automated certificate lifecycle management (CLM).",
                    json.dumps({"expired_endpoints": exp_ssl})
                )))
            if not cves_list and not hr_ports and exp_ssl == 0:
                st = ", ".join(stack_list[:4]) or "Standard Web Edge"
                signal_rows.append(clean((
                    cid, "Verified Edge Infrastructure Footprint", "Low", 0.85,
                    f"Active footprint on {hosting} ({asset_cnt} endpoints; stack: {st}).",
                    "Use verified hosting & tech-stack telemetry for account qualification.",
                    json.dumps({"hosting": hosting})
                )))

        execute_values(
            cur,
            """UPDATE companies AS c SET
                asset_count = v.asset_cnt, open_ports = v.ports::int[], tech_stack = v.stack::text[],
                cve_count = v.cve_cnt, top_cves = v.top_cves::text[], expired_ssl_count = v.exp_ssl,
                high_risk_port_count = v.hr_cnt, exposure_score = v.score, risk_tier = v.tier,
                updated_at = NOW()
               FROM (VALUES %s) AS v(cid, asset_cnt, ports, stack, cve_cnt, top_cves, exp_ssl, hr_cnt, score, tier)
               WHERE c.id = v.cid""",
            update_rows
        )

        if signal_rows:
            execute_values(
                cur,
                """INSERT INTO cyber_signals (
                    company_id, signal_type, severity, confidence_score,
                    signal_summary, recommended_action, evidence
                ) VALUES %s
                ON CONFLICT (company_id, signal_type) DO UPDATE SET
                    severity = EXCLUDED.severity,
                    signal_summary = EXCLUDED.signal_summary,
                    evidence = EXCLUDED.evidence,
                    detected_at = NOW()""",
                signal_rows, page_size=2000
            )

        cur.execute(
            """INSERT INTO processed_files (file_hash, file_path, banners_resolved)
               VALUES (%s, %s, %s)
               ON CONFLICT (file_hash) DO UPDATE SET processed_at = NOW()""",
            (f_hash, data_path, sum(len(companies[d]["assets"]) for d in domains))
        )

    conn.commit()
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM companies")
        (n_comp,) = cur.fetchone()
        cur.execute("SELECT COUNT(*) FROM exposed_assets")
        (n_assets,) = cur.fetchone()
        cur.execute("SELECT COUNT(*) FROM cyber_signals")
        (n_sig,) = cur.fetchone()
    conn.close()
    print(f"Upsert complete -> Total Companies: {n_comp:,} | Total Assets: {n_assets:,} | Total Signals: {n_sig:,}")

if __name__ == "__main__":
    t0 = time.time()
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    if "--reset" in flags:
        reset_schema()
    target = args if args else DEFAULT_DATA_PATH
    load_to_postgres(target, force=("--force" in flags or "--reset" in flags))
    print(f"Done in {round(time.time() - t0, 1)}s.")
