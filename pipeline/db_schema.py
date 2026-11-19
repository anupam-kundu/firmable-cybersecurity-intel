import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def get_connection():
    if db_url := os.getenv("DATABASE_URL"):
        return psycopg2.connect(db_url)
    return psycopg2.connect(
        dbname=os.getenv("POSTGRES_DB", "firmable_intel"),
        user=os.getenv("POSTGRES_USER", "firmable"),
        password=os.getenv("POSTGRES_PASSWORD", "firmable_secret"),
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
    )

DDL = """
CREATE TABLE IF NOT EXISTS processed_files (
    file_hash TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    banners_read INT DEFAULT 0,
    banners_resolved INT DEFAULT 0,
    processed_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS companies (
    id SERIAL PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    company_name TEXT NOT NULL,
    resolution_source TEXT,
    country_code TEXT,
    city TEXT,
    primary_asn TEXT,
    hosting_provider TEXT,
    asset_count INT DEFAULT 0,
    open_ports INT[] DEFAULT '{}',
    tech_stack TEXT[] DEFAULT '{}',
    cve_count INT DEFAULT 0,
    max_cvss NUMERIC(4,1) DEFAULT 0.0,
    top_cves TEXT[] DEFAULT '{}',
    expired_ssl_count INT DEFAULT 0,
    high_risk_port_count INT DEFAULT 0,
    exposure_score INT DEFAULT 0,
    risk_tier TEXT,
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS exposed_assets (
    id SERIAL PRIMARY KEY,
    company_id INT REFERENCES companies(id) ON DELETE CASCADE,
    ip_str TEXT NOT NULL,
    port INT NOT NULL,
    transport TEXT,
    product TEXT,
    version TEXT,
    asn TEXT,
    isp TEXT,
    country_code TEXT,
    ssl_expired BOOLEAN DEFAULT FALSE,
    ssl_issuer TEXT,
    http_title TEXT,
    vuln_ids TEXT[] DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',
    banner_snippet TEXT,
    first_seen_at TIMESTAMP DEFAULT NOW(),
    last_seen_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(company_id, ip_str, port)
);

CREATE TABLE IF NOT EXISTS cyber_signals (
    id SERIAL PRIMARY KEY,
    company_id INT REFERENCES companies(id) ON DELETE CASCADE,
    signal_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence_score NUMERIC(4,2) NOT NULL,
    signal_summary TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    evidence JSONB,
    detected_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(company_id, signal_type)
);

CREATE INDEX IF NOT EXISTS idx_companies_score ON companies(exposure_score DESC);
CREATE INDEX IF NOT EXISTS idx_companies_tier ON companies(risk_tier);
CREATE INDEX IF NOT EXISTS idx_assets_company ON exposed_assets(company_id);
CREATE INDEX IF NOT EXISTS idx_signals_company ON cyber_signals(company_id);
"""

def init_schema():
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute(DDL)
    conn.commit()
    conn.close()

def reset_schema():
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("""
            DROP TABLE IF EXISTS processed_files CASCADE;
            DROP TABLE IF EXISTS cyber_signals CASCADE;
            DROP TABLE IF EXISTS exposed_assets CASCADE;
            DROP TABLE IF EXISTS companies CASCADE;
        """)
        cur.execute(DDL)
    conn.commit()
    conn.close()
    print("PostgreSQL schema reset and initialized.")

if __name__ == "__main__":
    reset_schema()
