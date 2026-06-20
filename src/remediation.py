"""
remediation.py
--------------
Fetches the latest safe version of a package from the appropriate
registry (PyPI for Python, npm registry for JavaScript) and generates
a concrete remediation recommendation per risky package.

For each scored package it answers:
  - What is the latest available version in its registry?
  - Is the current version outdated?
  - What should the user do — upgrade, pin, or replace?

Both PyPI and npm registry APIs are public — no key required.
"""

import time
import requests


PYPI_API = "https://pypi.org/pypi/{package}/json"
NPM_API  = "https://registry.npmjs.org/{package}/latest"


# ── Registry lookups ──────────────────────────────────────────────────────────

def fetch_latest_pypi_version(package_name: str) -> str | None:
    """
    Fetch the latest stable version of a package from PyPI.
    Returns version string like "2.31.0", or None if lookup fails.
    """
    url = PYPI_API.format(package=package_name)
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 404:
            return None  # package not found on PyPI
        response.raise_for_status()
        data = response.json()
        return data["info"]["version"]
    except requests.RequestException:
        return None


def fetch_latest_npm_version(package_name: str) -> str | None:
    """
    Fetch the latest stable version of a package from the npm registry.
    Returns version string like "1.17.0", or None if lookup fails.
    """
    url = NPM_API.format(package=package_name)
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 404:
            return None  # package not found on npm
        response.raise_for_status()
        data = response.json()
        return data.get("version")
    except requests.RequestException:
        return None


def fetch_latest_version(package_name: str, ecosystem: str = "pypi") -> str | None:
    """
    Dispatch to the correct registry based on ecosystem.
    """
    if ecosystem == "npm":
        return fetch_latest_npm_version(package_name)
    return fetch_latest_pypi_version(package_name)


# ── Remediation logic ──────────────────────────────────────────────────────────

def generate_remediation(scored_package: dict, latest_version: str | None) -> dict:
    """
    Generate a remediation recommendation for a single scored package.

    Returns a remediation dict:
    {
        "action":       str,   # UPGRADE / PIN / MONITOR / REPLACE / INVESTIGATE
        "reason":       str,   # one-line explanation
        "suggestion":   str,   # concrete fix — syntax depends on ecosystem
        "latest":       str,   # latest registry version or None
        "is_outdated":  bool,  # current version != latest
    }
    """
    name        = scored_package["name"]
    version     = scored_package.get("version")
    pinned      = scored_package.get("pinned", False)
    ecosystem   = scored_package.get("ecosystem", "pypi")
    score       = scored_package["score"]
    label       = score["label"]
    findings    = scored_package["findings"]
    any_kev     = findings["any_kev"]

    is_outdated = (
        bool(latest_version)
        and bool(version)
        and version != latest_version
    )

    # Ecosystem-specific version pin syntax
    def pin(v: str) -> str:
        if ecosystem == "npm":
            return f"{name}@{v}"
        return f"{name}=={v}"

    registry_name = "npm registry" if ecosystem == "npm" else "PyPI"

    # ── Determine action and suggestion ───────────────────────────────────────

    if label == "CRITICAL" and any_kev:
        action     = "UPGRADE IMMEDIATELY"
        reason     = "Actively exploited vulnerability — treat as incident-level priority"
        suggestion = pin(latest_version) if latest_version else f"upgrade {name} — check {registry_name} for latest"

    elif label == "CRITICAL":
        action     = "UPGRADE NOW"
        reason     = "Critical severity CVE with high exploitation probability"
        suggestion = pin(latest_version) if latest_version else f"upgrade {name} — check {registry_name} for latest"

    elif label == "HIGH" and is_outdated:
        action     = "UPGRADE"
        reason     = "High severity CVE and a newer version is available"
        suggestion = pin(latest_version)

    elif label == "HIGH" and not is_outdated:
        action     = "INVESTIGATE"
        reason     = "High severity CVE — already on latest version, check if patch exists or apply mitigations"
        suggestion = f"Review {name} CVEs and apply available mitigations"

    elif label == "MEDIUM" and is_outdated:
        action     = "UPGRADE"
        reason     = "Newer version available — likely includes security fixes"
        suggestion = pin(latest_version)

    elif label == "MEDIUM":
        action     = "MONITOR"
        reason     = "Medium severity — schedule review in next sprint"
        suggestion = f"Keep {name} pinned and monitor for patches"

    elif not pinned and latest_version:
        action     = "PIN VERSION"
        reason     = "Unpinned dependency can silently upgrade to a vulnerable version"
        suggestion = pin(latest_version)

    else:
        action     = "NO ACTION"
        reason     = "No significant risk signals detected"
        suggestion = f"Keep {name} as-is"

    return {
        "action":      action,
        "reason":      reason,
        "suggestion":  suggestion,
        "latest":      latest_version,
        "is_outdated": is_outdated,
    }


# ── Enrich all scored packages ─────────────────────────────────────────────────

def add_remediation(scored_packages: list) -> list:
    """
    Fetch latest registry versions (PyPI or npm) and attach remediation
    to all scored packages. Only fetches registry data for packages with
    risk score > 0 or unpinned. Clean packages get a lightweight
    no-action entry.
    """
    print(f"\n{'='*50}")
    print(f"  AgentSCM — Remediation Suggestions")
    print(f"{'='*50}\n")

    result = []
    for p in scored_packages:
        score = p["score"]["total"]
        pinned = p.get("pinned", False)
        name = p["name"]
        ecosystem = p.get("ecosystem", "pypi")
        registry = "npm" if ecosystem == "npm" else "PyPI"

        # Only hit the registry if there's something to say
        if score > 0 or not pinned:
            print(f"  [{registry}] Checking latest version for {name}...")
            latest = fetch_latest_version(name, ecosystem)
        else:
            latest = None

        remediation = generate_remediation(p, latest)

        enriched = dict(p)
        enriched["remediation"] = remediation
        result.append(enriched)

    return result


def print_remediation_report(packages: list) -> None:
    """Print remediation recommendations to terminal."""

    print(f"\n{'='*60}")
    print(f"  AgentSCM — Remediation Report")
    print(f"{'='*60}")

    actionable = [p for p in packages if p["remediation"]["action"] != "NO ACTION"]
    clean      = [p for p in packages if p["remediation"]["action"] == "NO ACTION"]

    if actionable:
        print(f"\n  Packages requiring action:\n")
        for p in actionable:
            r = p["remediation"]
            s = p["score"]
            print(f"  {s['emoji']} {p['name']}")
            print(f"     Action     : {r['action']}")
            print(f"     Reason     : {r['reason']}")
            print(f"     Fix        : {r['suggestion']}")
            if r["latest"] and p.get("version") and p["version"] != r["latest"]:
                print(f"     Current    : {p['version']}  →  Latest: {r['latest']}")
            print()

    if clean:
        print(f"  ✅ {len(clean)} package(s) need no action: "
              f"{', '.join(p['name'] for p in clean)}\n")


# ── Quick test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Mock scored packages — no API calls to NVD/KEV needed for this test
    mock_scored = [
        {
            "name": "pillow", "version": "9.0.0", "version_spec": "==", "pinned": True,
            "score": {"total": 90, "label": "CRITICAL", "emoji": "🔴",
                      "breakdown": {"cvss": 40, "kev": 30, "epss": 20, "unpinned": 0},
                      "reasons": ["Critical CVE (CVSS 9.8)", "In CISA KEV"]},
            "findings": {"total_cves": 3, "any_kev": True, "kev_hits": ["CVE-2022-22816"],
                         "highest_cvss": 9.8, "highest_epss": 0.82, "cves": []},
        },
        {
            "name": "requests", "version": "2.28.1", "version_spec": "==", "pinned": True,
            "score": {"total": 35, "label": "MEDIUM", "emoji": "🟡",
                      "breakdown": {"cvss": 25, "kev": 0, "epss": 10, "unpinned": 0},
                      "reasons": ["High severity CVE (CVSS 7.5)"]},
            "findings": {"total_cves": 1, "any_kev": False, "kev_hits": [],
                         "highest_cvss": 7.5, "highest_epss": 0.45, "cves": []},
        },
        {
            "name": "numpy", "version": None, "version_spec": None, "pinned": False,
            "score": {"total": 5, "label": "LOW", "emoji": "🟢",
                      "breakdown": {"cvss": 0, "kev": 0, "epss": 0, "unpinned": 5},
                      "reasons": ["Version not pinned"]},
            "findings": {"total_cves": 0, "any_kev": False, "kev_hits": [],
                         "highest_cvss": 0.0, "highest_epss": 0.0, "cves": []},
        },
        {
            "name": "flask", "version": "2.3.0", "version_spec": "==", "pinned": True,
            "score": {"total": 0, "label": "LOW", "emoji": "🟢",
                      "breakdown": {"cvss": 0, "kev": 0, "epss": 0, "unpinned": 0},
                      "reasons": ["No significant risk signals detected"]},
            "findings": {"total_cves": 0, "any_kev": False, "kev_hits": [],
                         "highest_cvss": 0.0, "highest_epss": 0.0, "cves": []},
        },
    ]

    packages_with_remediation = add_remediation(mock_scored)
    print_remediation_report(packages_with_remediation)
