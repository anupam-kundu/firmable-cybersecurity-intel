import json
import time
from psycopg2.extras import execute_values
from pipeline.db_schema import get_connection, reset_schema
from pipeline.resolver import HIGH_RISK_PORTS, compute_risk_score
from pipeline.parser import parse_and_aggregate

def clean(row):
    return tuple(v.replace("\x00", "") if isinstance(v, str) else v for v in row)

def load_to_postgres(companies: dict):
    reset_schema()
    conn = get_connection()
    domains = sorted(companies.keys())
    company_rows = []

    for dom in domains:
        c = companies[dom]
        score, tier = compute_risk_score(
            len(c["assets"]), len(c["cves"]), c["max_cvss"],
            c["expired_ssl_count"], c["high_risk_ports"], c["tags"]
        )
        company_rows.append(clean((
            c["domain"], c["company_name"], c["resolution_source"],
            c["country_code"], c["city"], c["primary_asn"], c["hosting_provider"],
            len(c["assets"]), sorted(c["ports"])[:30], sorted(c["tech_stack"])[:20],
            len(c["cves"]), round(c["max_cvss"], 1), sorted(c["cves"], reverse=True)[:10],
            c["expired_ssl_count"], len(c["high_risk_ports"]), score, tier
        )))

    with conn.cursor() as cur:
        inserted = execute_values(
            cur,
            """INSERT INTO companies (
                domain, company_name, resolution_source, country_code, city,
                primary_asn, hosting_provider, asset_count, open_ports, tech_stack,
                cve_count, max_cvss, top_cves, expired_ssl_count, high_risk_port_count,
                exposure_score, risk_tier
            ) VALUES %s RETURNING id, domain""",
            company_rows, fetch=True
        )
        dom_id = {r[1]: r[0] for r in inserted}
        asset_rows, signal_rows = [], []

        for dom in domains:
            cid, c = dom_id[dom], companies[dom]
            asset_rows.extend(clean((cid, *a)) for a in c["assets"].values())

            if c["cves"]:
                top3 = ", ".join(sorted(c["cves"], reverse=True)[:3])
                sev = "Critical" if c["max_cvss"] >= 9.0 else "High"
                signal_rows.append(clean((
                    cid, "Active CVE Exposure", sev, 0.94,
                    f"{len(c['cves'])} known CVEs detected (Max CVSS {c['max_cvss']:.1f}: {top3}).",
                    "Prioritize vulnerability remediation outreach; pitch automated attack-surface patching.",
                    json.dumps({"cve_count": len(c["cves"]), "max_cvss": c["max_cvss"]})
                )))
            if c["high_risk_ports"]:
                p_names = [f"{p} ({HIGH_RISK_PORTS[p][0]})" for p in sorted(c["high_risk_ports"])]
                signal_rows.append(clean((
                    cid, "High-Risk Service / DB Exposure", "High", 0.91,
                    f"Publicly reachable sensitive services: {', '.join(p_names)}.",
                    "Alert security leadership regarding zero-trust segmentation and firewall hardening.",
                    json.dumps({"exposed_ports": sorted(c["high_risk_ports"])})
                )))
            if c["expired_ssl_count"] > 0:
                signal_rows.append(clean((
                    cid, "SSL/TLS Certificate Hygiene Failure", "Medium", 0.96,
                    f"{c['expired_ssl_count']} public endpoint(s) serving expired TLS certificates.",
                    "Engage DevOps/SecOps team with automated certificate lifecycle management (CLM).",
                    json.dumps({"expired_endpoints": c["expired_ssl_count"]})
                )))
            if not c["cves"] and not c["high_risk_ports"] and c["expired_ssl_count"] == 0:
                stack = ", ".join(sorted(c["tech_stack"])[:4]) or "Standard Web Edge"
                signal_rows.append(clean((
                    cid, "Verified Edge Infrastructure Footprint", "Low", 0.85,
                    f"Active footprint on {c['hosting_provider']} ({len(c['assets'])} endpoints; stack: {stack}).",
                    "Use verified hosting & tech-stack telemetry for account qualification.",
                    json.dumps({"hosting": c["hosting_provider"]})
                )))

        execute_values(cur, """INSERT INTO exposed_assets (
            company_id, ip_str, port, transport, product, version, asn, isp,
            country_code, ssl_expired, ssl_issuer, http_title, vuln_ids, tags, banner_snippet
        ) VALUES %s""", asset_rows, page_size=2000)

        execute_values(cur, """INSERT INTO cyber_signals (
            company_id, signal_type, severity, confidence_score,
            signal_summary, recommended_action, evidence
        ) VALUES %s""", signal_rows, page_size=2000)

    conn.commit()
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM companies")
        n_comp = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM exposed_assets")
        n_assets = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM cyber_signals")
        n_sig = cur.fetchone()[0]
        cur.execute("""SELECT risk_tier, exposure_score, domain, company_name, country_code, cve_count, max_cvss
                       FROM companies ORDER BY exposure_score DESC, cve_count DESC LIMIT 5""")
        top5 = cur.fetchall()
    conn.close()

    print(f"\nLoaded -> Companies: {n_comp:,} | Assets: {n_assets:,} | Signals: {n_sig:,}")
    for r in top5:
        print(f"  [{r[0]:8s} | {r[1]:3d}] {r[2]:26s} ({r[3][:22]:22s}) | {r[4]} | CVEs: {r[5]} (Max {r[6]})")

if __name__ == "__main__":
    t0 = time.time()
    load_to_postgres(parse_and_aggregate())
    print(f"Done in {round(time.time() - t0, 1)}s.")
