"""
enricher.py
-----------
Stage 2: For each parsed package, fetch security context from 3 sources:

  1. NVD API       — known CVEs and CVSS severity scores
  2. CISA KEV      — is this CVE actively exploited in the wild?
  3. FIRST EPSS    — probability this CVE gets exploited in next 30 days

All three APIs are free and public. NVD works without a key but is
rate-limited to 5 requests/30s. With a key it allows 50 requests/30s.

Set your NVD key in a .env file:
    NVD_API_KEY=your-key-here

Or pass it directly to EnricherConfig.
"""

import os
import time
import requests
from dataclasses import dataclass, field
from dotenv import load_dotenv


# ── Configuration ──────────────────────────────────────────────────────────────

@dataclass
class EnricherConfig:
    nvd_api_key: str = ""
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_fallback_url: str = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
    epss_base_url: str = "https://api.first.org/data/v1/epss"

    # Rate limiting: NVD allows 5 req/30s without key, 50 req/30s with key
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
    Tries CISA directly first, falls back to GitHub mirror.
    Uses a module-level cache so we only fetch it once per session.
    """
    global _kev_cache, _kev_loaded

    if _kev_loaded:
        return _kev_cache

    print("  [KEV] Downloading CISA Known Exploited Vulnerabilities catalog...")
    urls_to_try = [config.kev_url, config.kev_fallback_url]

    for url in urls_to_try:
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            data = response.json()

            _kev_cache = {
                vuln["cveID"]
                for vuln in data.get("vulnerabilities", [])
            }
            _kev_loaded = True
            source = "CISA" if url == config.kev_url else "GitHub mirror"
            print(f"  [KEV] Loaded {len(_kev_cache)} known exploited CVEs (source: {source}).")
            return _kev_cache

        except requests.RequestException as e:
            print(f"  [KEV] Could not load from {url}: {e}")

    print("  [KEV] Warning: All KEV sources failed. KEV enrichment disabled.")
    _kev_cache = set()
    _kev_loaded = True
    return _kev_cache


# ── NVD Lookup ─────────────────────────────────────────────────────────────────

def fetch_nvd_cves(package: dict, config: EnricherConfig) -> list:
    """
    Query NVD for CVEs matching this package name and version.

    Returns a list of CVE dicts, each with:
        cve_id, description, cvss_score, cvss_severity, published_date
    """
    headers = {}
    if config.nvd_api_key:
        headers["apiKey"] = config.nvd_api_key

    params = {
        "keywordSearch": package["name"],
        "resultsPerPage": 10,
    }

    try:
        time.sleep(config.request_delay)
        response = requests.get(
            config.nvd_base_url,
            headers=headers,
            params=params,
            timeout=15
        )
        response.raise_for_status()
        data = response.json()

    except requests.RequestException as e:
        print(f"  [NVD] Warning: Could not fetch CVEs for {package['name']}: {e}")
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        # Only keep CVEs that clearly mention this package in the description
        if package["name"].lower() not in description.lower():
            continue

        # Extract CVSS score — try v3.1 first, fall back to v3.0, then v2
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_severity = "UNKNOWN"

        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        published = cve.get("published", "")[:10]

        cves.append({
            "cve_id": cve_id,
            "description": description[:300] + "..." if len(description) > 300 else description,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "published_date": published,
        })

    return cves


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
    print(f"  [NVD] Fetching CVEs for {package['name']} ...")
    cves = fetch_nvd_cves(package, config)

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
    sys.path.insert(0, ".")
    from src.parser import parse_requirements

    # Load .env securely
    load_dotenv()

    config = EnricherConfig(nvd_api_key=os.environ.get("NVD_API_KEY", ""))

    if config.nvd_api_key:
        print("  NVD API key loaded ✓")
    else:
        print("  No NVD API key found — slower unauthenticated mode")

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

# NOTE: The __main__ block below is for quick manual testing only.
# For real runs, use: from src.config import load_config
# That loads your NVD key from .env cleanly without exposing it.
