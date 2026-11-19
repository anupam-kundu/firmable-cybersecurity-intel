import os
import re
import tldextract

BLOCKLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "infra_blocklist.txt")

def load_infra_blocklist(path: str = BLOCKLIST_PATH) -> set[str]:
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}

INFRA_SUFFIXES = load_infra_blocklist()
EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

HIGH_RISK_PORTS = {
    21: ("FTP", 12), 23: ("Telnet", 22), 445: ("SMB File Sharing", 25),
    1433: ("MS SQL Server", 22), 1521: ("Oracle DB", 22), 2375: ("Unencrypted Docker API", 35),
    3306: ("MySQL Database", 18), 3389: ("RDP Remote Desktop", 24), 5432: ("PostgreSQL Database", 18),
    5900: ("VNC Remote Desktop", 24), 6379: ("Redis Cache", 28), 8080: ("HTTP Alt / Admin Proxy", 8),
    8443: ("HTTPS Alt / Management UI", 8), 9200: ("Elasticsearch", 30),
    11211: ("Memcached", 26), 27017: ("MongoDB", 30),
}

NOISE_HOST_RE = re.compile(r"^(?:ip|host|static|dyn|dhcp|dsl|cable|ppp|cpe|node|vps|srv|server)[-_]?\d")

def extract_root_domain(candidate: str) -> str | None:
    if not candidate or not isinstance(candidate, str):
        return None
    d = candidate.strip().lower().lstrip("*.").rstrip(".")
    if any(ch in d for ch in ("@", "/", " ", ":")) or "." not in d:
        return None
    ext = EXTRACTOR(d)
    if not ext.domain or not ext.suffix:
        return None
    root = f"{ext.domain}.{ext.suffix}"
    if root in INFRA_SUFFIXES or d in INFRA_SUFFIXES or ext.suffix in INFRA_SUFFIXES:
        return None
    if NOISE_HOST_RE.match(ext.domain):
        return None
    return root

def resolve_company_domain(rec: dict) -> tuple[str | None, str]:
    for dom in rec.get("domains") or []:
        if root := extract_root_domain(dom):
            return root, "shodan_domains"
    cert = ((rec.get("ssl") or {}).get("cert") or {})
    if root := extract_root_domain((cert.get("subject") or {}).get("CN")):
        return root, "ssl_cert_cn"
    for host in rec.get("hostnames") or []:
        if root := extract_root_domain(host):
            return root, "ptr_hostname"
    return None, "unresolved"

def clean_org_name(rec: dict, domain: str) -> str:
    cert_org = (((rec.get("ssl") or {}).get("cert") or {}).get("subject") or {}).get("O")
    raw_org = str(cert_org or rec.get("org") or rec.get("isp") or "").strip()
    generic_isps = {
        "amazon.com, inc.", "amazon data services", "google llc", "microsoft corporation",
        "cloudflare, inc.", "digitalocean, llc", "ovh sas", "hetzner online gmbh",
        "akamai technologies, inc.", "linode, llc", "vultr holdings, llc", "oracle corporation"
    }
    if not raw_org or raw_org.lower() in generic_isps:
        return EXTRACTOR(domain).domain.replace("-", " ").replace("_", " ").title()
    return raw_org[:180]

def classify_hosting(asn: str, isp: str, org: str) -> str:
    blob = f"{asn} {isp} {org}".lower()
    if any(k in blob for k in ["amazon", "aws", "as16509", "as14618"]):
        return "AWS"
    if any(k in blob for k in ["microsoft", "azure", "as8075"]):
        return "Microsoft Azure"
    if any(k in blob for k in ["google", "gcp", "as15169", "as396982"]):
        return "Google Cloud"
    if any(k in blob for k in ["cloudflare", "as13335"]):
        return "Cloudflare"
    if any(k in blob for k in ["digitalocean", "linode", "vultr", "hetzner", "ovh"]):
        return "Cloud / VPS"
    return "Corporate / Dedicated ASN"

def compute_risk_score(asset_cnt: int, cve_cnt: int, max_cvss: float, exp_ssl: int, hr_ports: set, tags: set) -> tuple[int, str]:
    score = 10
    score += min(35, cve_cnt * 4 + int(max_cvss * 2))
    score += min(25, sum(HIGH_RISK_PORTS[p][1] for p in hr_ports))
    score += min(15, exp_ssl * 8)
    score += min(10, max(0, asset_cnt - 1) * 3)
    if {"self-signed", "database", "ics"} & tags:
        score += 8
    score = min(100, score)
    tier = "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 30 else "Low"
    return score, tier
