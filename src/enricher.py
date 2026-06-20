"""
enricher.py
-----------
Stage 2: For each parsed package, fetch security context from 3 sources:

  1. OSV API       — known CVEs/vulns, purpose-built for package lookups (no API key needed)
  2. CISA KEV      — is this CVE actively exploited in the wild?
  3. FIRST EPSS    — probability this CVE gets exploited in next 30 days

OSV (Open Source Vulnerabilities) is the primary CVE source — it returns only
vulnerabilities that actually affect the specific package and version, unlike
NVD keyword search which returns noisy, unrelated results.

KEV fallback chain (tried in order):
  1. CISA direct feed
  2. GitHub mirror (cisagov/kev-data)
  3. VulnCheck KEV (set VULNCHECK_API_KEY in .env)

Set your keys in a .env file:
    NVD_API_KEY=your-nvd-key (optional, kept for legacy)
    VULNCHECK_API_KEY=your-vulncheck-token (for KEV fallback)
"""

import os
import time
import requests
from dataclasses import dataclass, field


# ── Configuration ──────────────────────────────────────────────────────────────

@dataclass
class EnricherConfig:
    nvd_api_key: str = ""
    vulncheck_api_key: str = ""
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    vulncheck_nvd_url: str = "https://api.vulncheck.com/v3/index/nist-nvd2"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_fallback_url: str = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
    vulncheck_kev_url: str = "https://api.vulncheck.com/v3/index/vulncheck-kev"
    epss_base_url: str = "https://api.first.org/data/v1/epss"

    # Rate limiting: NVD allows 5 req/30s without key, 50 req/30s with key
    # VulnCheck has generous rate limits for community tier
    request_delay: float = field(init=False)

    def __post_init__(self):
        self.request_delay = 1.0 if self.nvd_api_key else 6.5


# ── KEV Cache ──────────────────────────────────────────────────────────────────
# We download the full KEV list once per session and check against it locally.
# This is faster and more polite than querying for every CVE individually.

_kev_cache: set = set()
_kev_loaded: bool = False


def load_kev_catalog(config: EnricherConfig) -> set:
    """
    Download CISA KEV catalog once and return a set of CVE IDs.

    Fallback chain:
      1. CISA direct
      2. GitHub mirror
      3. VulnCheck KEV (if VULNCHECK_API_KEY set)
    """
    global _kev_cache, _kev_loaded

    if _kev_loaded:
        return _kev_cache

    print("  [KEV] Downloading CISA Known Exploited Vulnerabilities catalog...")

    # Sources 1 & 2: CISA and GitHub mirror (same JSON format)
    standard_urls = [
        (config.kev_url, "CISA", None),
        (config.kev_fallback_url, "GitHub mirror", None),
    ]

    for url, source_name, headers in standard_urls:
        try:
            response = requests.get(url, headers=headers or {}, timeout=15)
            response.raise_for_status()
            data = response.json()
            _kev_cache = {
                vuln["cveID"]
                for vuln in data.get("vulnerabilities", [])
            }
            _kev_loaded = True
            print(f"  [KEV] Loaded {len(_kev_cache)} known exploited CVEs (source: {source_name}).")
            return _kev_cache
        except requests.RequestException as e:
            print(f"  [KEV] Could not load from {source_name}: {e}")

    # Source 3: VulnCheck KEV (different JSON format — paginated)
    if config.vulncheck_api_key:
        try:
            print("  [KEV] Trying VulnCheck KEV as fallback...")
            headers = {"Authorization": f"Bearer {config.vulncheck_api_key}"}
            response = requests.get(config.vulncheck_kev_url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            # VulnCheck KEV format: data._note or data.data list with cve field
            _kev_cache = set()
            for item in data.get("data", []):
                # Each item may have a list of CVE IDs
                for cve in item.get("cve", []):
                    if isinstance(cve, str):
                        _kev_cache.add(cve)
            _kev_loaded = True
            print(f"  [KEV] Loaded {len(_kev_cache)} known exploited CVEs (source: VulnCheck KEV).")
            return _kev_cache
        except requests.RequestException as e:
            print(f"  [KEV] Could not load from VulnCheck KEV: {e}")

    print("  [KEV] Warning: All KEV sources failed. KEV enrichment disabled.")
    _kev_cache = set()
    _kev_loaded = True
    return _kev_cache


# ── OSV Lookup ─────────────────────────────────────────────────────────────────
# OSV (Open Source Vulnerabilities) is purpose-built for package vulnerability
# lookup by name, ecosystem, and version. Unlike NVD keyword search, it returns
# ONLY vulnerabilities that actually affect the specific package — no noise.
# Free, no API key required. Used by pip-audit, Google, and GitHub internally.

OSV_API = "https://api.osv.dev/v1/query"

# Map our ecosystem names to OSV ecosystem names
OSV_ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm":  "npm",
}


def fetch_osv_cves(package: dict) -> list:
    """
    Query OSV for vulnerabilities affecting this specific package and version.

    OSV is purpose-built for this — no keyword noise, no false positives.
    Returns only CVEs that actually affect the package name + version given.

    Returns a list of CVE dicts, each with:
        cve_id, description, cvss_score, cvss_severity, published_date
    """
    ecosystem = package.get("ecosystem", "pypi")
    osv_ecosystem = OSV_ECOSYSTEM_MAP.get(ecosystem, "PyPI")

    payload = {
        "package": {
            "name": package["name"],
            "ecosystem": osv_ecosystem,
        }
    }

    # If we have an exact version, include it to get only version-specific vulns
    if package.get("version") and package.get("pinned"):
        payload["version"] = package["version"]

    try:
        response = requests.post(
            OSV_API,
            json=payload,
            timeout=(5, 15)
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        print(f"  [OSV] Failed for {package['name']}: {e}")
        return []

    cves = []
    for vuln in data.get("vulns", []):
        # OSV may have multiple IDs (CVE, GHSA, etc.) — prefer CVE
        aliases = vuln.get("aliases", [])
        cve_ids = [a for a in aliases if a.startswith("CVE-")]
        vuln_id = vuln.get("id", "")
        cve_id = cve_ids[0] if cve_ids else vuln_id

        # Get description from summary or details
        description = vuln.get("summary") or vuln.get("details", "No description available.")
        description = description[:300] + "..." if len(description) > 300 else description

        # Extract CVSS from severity — OSV provides severity as a list
        cvss_score = None
        cvss_severity = "UNKNOWN"

        for severity in vuln.get("severity", []):
            if severity.get("type") == "CVSS_V3":
                # OSV provides CVSS as a vector string — extract score from database_specific
                score = (vuln.get("database_specific") or {}).get("cvss", {})
                if isinstance(score, dict):
                    cvss_score = score.get("score")
                    cvss_severity = score.get("severity", "UNKNOWN")
                break

        # Also check ecosystem_specific for CVSS scores (PyPI/GitHub format)
        if cvss_score is None:
            db_specific = vuln.get("database_specific") or {}
            if "severity" in db_specific:
                sev = db_specific["severity"]
                severity_map = {
                    "CRITICAL": 9.5, "HIGH": 8.0,
                    "MODERATE": 6.5, "MEDIUM": 6.5, "LOW": 3.0
                }
                cvss_severity = sev.upper() if isinstance(sev, str) else "UNKNOWN"
                cvss_score = severity_map.get(cvss_severity)

        published = vuln.get("published", "")[:10]

        cves.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "published_date": published,
        })

    # Deduplicate by cve_id — OSV returns the same CVE from multiple sources
    # (e.g. GHSA + NVD). Keep the entry with the best CVSS score, or the
    # first entry if scores are equal (usually the more detailed description).
    seen = {}
    for cve in cves:
        cve_id = cve["cve_id"]
        if cve_id not in seen:
            seen[cve_id] = cve
        else:
            existing_score = seen[cve_id]["cvss_score"] or 0
            new_score = cve["cvss_score"] or 0
            if new_score > existing_score:
                seen[cve_id] = cve

    return list(seen.values())


# ── EPSS Lookup ────────────────────────────────────────────────────────────────

def fetch_epss_scores(cve_ids: list, config: EnricherConfig) -> dict:
    """
    Fetch EPSS scores for a list of CVE IDs from FIRST's API.
    Returns a dict mapping CVE ID -> EPSS score (0.0 to 1.0).

    Score of 0.95 means 95% probability of exploitation in next 30 days.
    """
    if not cve_ids:
        return {}

    cve_param = ",".join(cve_ids)

    try:
        response = requests.get(
            config.epss_base_url,
            params={"cve": cve_param},
            timeout=15
        )
        response.raise_for_status()
        data = response.json()

    except requests.RequestException as e:
        print(f"  [EPSS] Warning: Could not fetch EPSS scores: {e}")
        return {}

    return {
        item["cve"]: float(item.get("epss", 0.0))
        for item in data.get("data", [])
    }


# ── Main Enrichment Function ───────────────────────────────────────────────────

def enrich_package(package: dict, kev_catalog: set, config: EnricherConfig) -> dict:
    """
    Enrich a single package with CVE, KEV, and EPSS data.

    Returns the package dict with an added 'findings' key containing
    all security context for this package.
    """
    print(f"  [OSV] Fetching CVEs for {package['name']} ...")
    cves = fetch_osv_cves(package)

    cve_ids = [c["cve_id"] for c in cves]
    kev_hits = [cve_id for cve_id in cve_ids if cve_id in kev_catalog]

    epss_scores = {}
    if cve_ids:
        epss_scores = fetch_epss_scores(cve_ids, config)

    # Attach EPSS and KEV status to each CVE for convenience
    for cve in cves:
        cve["epss_score"] = epss_scores.get(cve["cve_id"], 0.0)
        cve["in_kev"] = cve["cve_id"] in kev_catalog

    highest_cvss = max((c["cvss_score"] for c in cves if c["cvss_score"]), default=0.0)
    highest_epss = max((c["epss_score"] for c in cves), default=0.0)

    enriched = dict(package)
    enriched["findings"] = {
        "cves": cves,
        "kev_hits": kev_hits,
        "epss_scores": epss_scores,
        "highest_cvss": highest_cvss,
        "highest_epss": highest_epss,
        "any_kev": len(kev_hits) > 0,
        "total_cves": len(cves),
    }

    return enriched


def enrich_all(packages: list, config: EnricherConfig) -> list:
    """
    Enrich all packages from the parser output.
    Downloads KEV catalog once, then processes each package sequentially.
    """
    print(f"\n{'='*50}")
    print(f"  AgentSCM — Stage 2: Enrichment")
    print(f"{'='*50}")
    print(f"  Enriching {len(packages)} packages...\n")

    kev_catalog = load_kev_catalog(config)

    enriched_packages = []
    for i, package in enumerate(packages, 1):
        print(f"  [{i}/{len(packages)}] {package['name']}")
        enriched = enrich_package(package, kev_catalog, config)
        enriched_packages.append(enriched)

    print(f"\n  Done. Enrichment complete for {len(enriched_packages)} packages.")
    return enriched_packages


def print_enrichment_summary(enriched_packages: list) -> None:
    """Print a quick enrichment summary to terminal."""
    print(f"\n{'='*50}")
    print(f"  AgentSCM — Enrichment Summary")
    print(f"{'='*50}")

    for p in enriched_packages:
        f = p["findings"]
        kev_flag = " ⚠ KEV" if f["any_kev"] else ""
        cve_count = f["total_cves"]
        cvss = f["highest_cvss"]
        epss = f["highest_epss"]

        status = "CLEAN" if cve_count == 0 else f"{cve_count} CVE(s)"
        print(f"  {p['name']:<25} {status:<12} CVSS:{cvss:<6} EPSS:{epss:.2f}{kev_flag}")

    print()


# ── Quick test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import json
    from dotenv import load_dotenv

    sys.path.insert(0, ".")
    from src.parser import parse_requirements

    # Load .env directly — no separate config file needed
    load_dotenv()
    config = EnricherConfig(
        nvd_api_key=os.environ.get("NVD_API_KEY", ""),
        vulncheck_api_key=os.environ.get("VULNCHECK_API_KEY", ""),
    )

    if config.nvd_api_key:
        print("  NVD API key loaded ✓")
    else:
        print("  No NVD API key — unauthenticated mode")

    if config.vulncheck_api_key:
        print("  VulnCheck API key loaded ✓ (NVD++ fallback enabled)")
    else:
        print("  No VulnCheck API key — add VULNCHECK_API_KEY to .env for NVD fallback")

    file = sys.argv[1] if len(sys.argv) > 1 else "data/samples/requirements.txt"
    packages, _ = parse_requirements(file)

    # For quick testing, only enrich first 3 packages
    test_packages = packages[:3]
    print(f"\n  (Testing with first {len(test_packages)} packages only)\n")

    enriched = enrich_all(test_packages, config)
    print_enrichment_summary(enriched)

    output_path = "data/enriched_sample.json"
    os.makedirs("data", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(enriched, f, indent=2)
    print(f"  Full enriched data saved to: {output_path}\n")