"""
pipeline.py
-----------
The main entry point for AgentSCM.

Auto-detects the dependency file type and routes to the right parser:
    requirements.txt   -> Python / PyPI ecosystem
    package-lock.json  -> npm / JavaScript ecosystem
    package.json       -> npm fallback (direct deps only, version ranges)

Then wires all stages together:
    Stage 1: parser      — reads dependency file
    Stage 2: enricher     — fetches CVE / KEV / EPSS data
    Stage 3: scorer       — ranks packages by risk
    Stage 4: remediation  — fetches latest safe version + recommended action

Usage:
    python src/pipeline.py data/samples/requirements.txt
    python src/pipeline.py data/samples/package-lock.json
    python src/pipeline.py /path/to/your/dependency/file
"""

import os
import sys
import json
from pathlib import Path
from dotenv import load_dotenv

# Make sure src/ is importable when running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.parser import parse_requirements, summarize_parse
from src.parser_npm import parse_package_lock, parse_package_json
from src.enricher import EnricherConfig, enrich_all, print_enrichment_summary
from src.scorer import score_all, print_score_report
from src.remediation import add_remediation, print_remediation_report


def detect_and_parse(file_path: str):
    """
    Detect the dependency file type by name and route to the
    correct parser. Returns (packages, skipped, ecosystem_label).
    """
    filename = Path(file_path).name.lower()

    if filename == "package-lock.json":
        packages, skipped = parse_package_lock(file_path)
        return packages, skipped, "npm (package-lock.json)"

    if filename == "package.json":
        packages, skipped = parse_package_json(file_path)
        return packages, skipped, "npm (package.json — version ranges, less precise)"

    # Default: treat as a Python requirements file
    packages, skipped = parse_requirements(file_path)
    return packages, skipped, "Python (requirements.txt)"


def run_pipeline(file_path: str, nvd_api_key: str = "", vulncheck_api_key: str = "") -> list:
    """
    Run the full AgentSCM pipeline on a requirements.txt file.

    Args:
        file_path:           path to requirements.txt or package-lock.json
        nvd_api_key:         NVD API key (loaded from .env by default)
        vulncheck_api_key:   VulnCheck token for NVD++ and KEV fallback

    Returns:
        List of scored + enriched package dicts, sorted by risk score.
    """

    print(f"\n{'='*60}")
    print(f"  AgentSCM — Agentic Supply Chain Monitor")
    print(f"  Target: {file_path}")
    print(f"{'='*60}\n")

    # ── Stage 1: Parse ─────────────────────────────────────────────
    print("  [Stage 1/4] Parsing dependency file...")
    try:
        packages, skipped, ecosystem_label = detect_and_parse(file_path)
    except (FileNotFoundError, ValueError) as e:
        print(f"\n  Error: {e}")
        sys.exit(1)

    print(f"  Detected: {ecosystem_label}")

    if ecosystem_label.startswith("Python"):
        summarize_parse(packages, skipped)
    else:
        direct = sum(1 for p in packages if p.get("is_direct"))
        print(f"  Total packages : {len(packages)}")
        print(f"  Direct deps    : {direct}")
        print(f"  Transitive     : {len(packages) - direct}")
        print(f"  Skipped        : {len(skipped)}\n")

    # ── Stage 2: Enrich ────────────────────────────────────────────
    print("  [Stage 2/4] Enriching with CVE / KEV / EPSS data...")
    config = EnricherConfig(
        nvd_api_key=nvd_api_key,
        vulncheck_api_key=vulncheck_api_key,
    )
    enriched = enrich_all(packages, config)
    print_enrichment_summary(enriched)

    # ── Stage 3: Score ─────────────────────────────────────────────
    print("  [Stage 3/4] Scoring and ranking packages...")
    scored = score_all(enriched)
    print_score_report(scored)

    # ── Stage 4: Remediation ────────────────────────────────────────
    print("  [Stage 4/4] Generating remediation suggestions...")
    scored = add_remediation(scored)
    print_remediation_report(scored)

    return scored


def save_results(scored: list, output_path: str = "data/results.json") -> None:
    """Save full pipeline results to JSON for the dashboard or further use."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Make a clean serializable copy — drop heavy fields for readability
    export = []
    for p in scored:
        export.append({
            "name":         p["name"],
            "version":      p.get("version"),
            "version_spec": p.get("version_spec"),
            "pinned":       p.get("pinned"),
            "raw_line":     p.get("raw_line"),
            "score":        p["score"],
            "findings": {
                "total_cves":   p["findings"]["total_cves"],
                "any_kev":      p["findings"]["any_kev"],
                "kev_hits":     p["findings"]["kev_hits"],
                "highest_cvss": p["findings"]["highest_cvss"],
                "highest_epss": p["findings"]["highest_epss"],
                "cves":         p["findings"]["cves"],
            }
        })

    with open(output_path, "w") as f:
        json.dump(export, f, indent=2)

    print(f"  Results saved to: {output_path}\n")


def print_action_summary(scored: list) -> None:
    """
    Print a concise what-to-do-now summary at the end of the run.
    Groups packages by risk label and gives a clear recommended action.
    """
    groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}

    for p in scored:
        label = p["score"]["label"]
        groups[label].append(p["name"])

    actions = {
        "CRITICAL": ("Patch or mitigate immediately", "🔴"),
        "HIGH":     ("Schedule patch this sprint",    "🟠"),
        "MEDIUM":   ("Review and plan remediation",   "🟡"),
        "LOW":      ("Monitor, no immediate action",  "🟢"),
    }

    print(f"\n{'='*60}")
    print(f"  AgentSCM — Recommended Actions")
    print(f"{'='*60}")

    for label, (action, emoji) in actions.items():
        pkgs = groups[label]
        if pkgs:
            print(f"\n  {emoji} {label} — {action}")
            for name in pkgs:
                print(f"     • {name}")

    total   = len(scored)
    at_risk = sum(1 for p in scored if p["score"]["total"] > 0)
    clean   = total - at_risk

    print(f"\n  {'─'*50}")
    print(f"  Total packages scanned : {total}")
    print(f"  Packages with risk     : {at_risk}")
    print(f"  Clean                  : {clean}")
    print()


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    load_dotenv()
    nvd_key = os.environ.get("NVD_API_KEY", "")
    vulncheck_key = os.environ.get("VULNCHECK_API_KEY", "")

    if len(sys.argv) < 2:
        print("\n  Usage: python src/pipeline.py <path/to/requirements.txt>")
        print("  Example: python src/pipeline.py data/samples/requirements.txt\n")
        sys.exit(1)

    file_path = sys.argv[1]

    scored = run_pipeline(file_path, nvd_api_key=nvd_key, vulncheck_api_key=vulncheck_key)
    print_action_summary(scored)
    save_results(scored)