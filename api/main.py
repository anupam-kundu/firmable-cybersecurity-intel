from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from psycopg2.extras import RealDictCursor
from pipeline.db_schema import get_connection

app = FastAPI(title="Firmable B2B Cyber Threat & Attack Surface Intelligence API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def serve_ui():
    return FileResponse("frontend/index.html")

@app.get("/api/summary")
def get_summary():
    conn = get_connection()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT COUNT(*) AS total_companies,
                   COALESCE(SUM(asset_count), 0) AS total_assets,
                   COALESCE(SUM(cve_count), 0) AS total_cves,
                   COUNT(*) FILTER (WHERE risk_tier = 'Critical') AS critical_companies,
                   COUNT(*) FILTER (WHERE risk_tier = 'High') AS high_risk_companies,
                   ROUND(AVG(exposure_score), 1) AS avg_exposure_score
            FROM companies
        """)
        kpis = cur.fetchone()
        cur.execute("SELECT risk_tier, COUNT(*) AS count FROM companies GROUP BY risk_tier ORDER BY count DESC")
        tiers = cur.fetchall()
        cur.execute("SELECT hosting_provider, COUNT(*) AS count FROM companies GROUP BY hosting_provider ORDER BY count DESC LIMIT 6")
        hosting = cur.fetchall()
        cur.execute("SELECT signal_type, severity, COUNT(*) AS count FROM cyber_signals GROUP BY signal_type, severity ORDER BY count DESC")
        signals = cur.fetchall()
    conn.close()
    return {"kpis": kpis, "tiers": tiers, "hosting": hosting, "signals": signals}

@app.get("/api/companies")
def list_companies(search: str = Query(default=""), risk_tier: str = Query(default=""), limit: int = Query(default=50, le=200)):
    conn = get_connection()
    clauses, params = [], []
    if search:
        clauses.append("(domain ILIKE %s OR company_name ILIKE %s OR array_to_string(top_cves, ',') ILIKE %s)")
        like = f"%{search}%"
        params.extend([like, like, like])
    if risk_tier:
        clauses.append("risk_tier = %s")
        params.append(risk_tier)
    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(f"""
            SELECT id, domain, company_name, country_code, city, hosting_provider,
                   asset_count, open_ports, tech_stack, cve_count, max_cvss,
                   top_cves, expired_ssl_count, high_risk_port_count, exposure_score, risk_tier
            FROM companies {where_sql}
            ORDER BY exposure_score DESC, cve_count DESC, asset_count DESC LIMIT %s
        """, params)
        rows = cur.fetchall()
    conn.close()
    return {"companies": rows}

@app.get("/api/companies/{company_id}")
def get_company_detail(company_id: int):
    conn = get_connection()
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM companies WHERE id = %s", (company_id,))
        company = cur.fetchone()
        if not company:
            conn.close()
            raise HTTPException(status_code=404, detail="Company not found")
        cur.execute("""
            SELECT ip_str, port, transport, product, version, asn, isp,
                   country_code, ssl_expired, ssl_issuer, http_title, vuln_ids, tags
            FROM exposed_assets WHERE company_id = %s ORDER BY port ASC LIMIT 100
        """, (company_id,))
        assets = cur.fetchall()
        cur.execute("""
            SELECT signal_type, severity, confidence_score, signal_summary, recommended_action, evidence
            FROM cyber_signals WHERE company_id = %s ORDER BY confidence_score DESC
        """, (company_id,))
        signals = cur.fetchall()
    conn.close()
    return {"company": company, "assets": assets, "signals": signals}
