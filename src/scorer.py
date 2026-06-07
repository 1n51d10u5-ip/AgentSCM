"""
scorer.py
---------
Stage 3: Takes enriched package data and produces a risk score
for each package, then ranks them from most to least dangerous.

Scoring factors:
  - CVSS severity     (up to 40 points)
  - KEV presence      (+30 points) — actively exploited right now
  - EPSS score        (up to +20 points) — exploitation probability
  - Unpinned version  (+5 points)  — silent upgrade risk

Final score is capped at 100 and mapped to a risk label:
  70-100 -> CRITICAL
  40-69  -> HIGH
  15-39  -> MEDIUM
  0-14   -> LOW
"""


# ── Weights ────────────────────────────────────────────────────────────────────

CVSS_CRITICAL_SCORE   = 40   # CVSS 9.0 - 10.0
CVSS_HIGH_SCORE       = 25   # CVSS 7.0 - 8.9
CVSS_MEDIUM_SCORE     = 10   # CVSS 4.0 - 6.9

KEV_SCORE             = 30   # actively exploited per CISA

EPSS_HIGH_SCORE       = 20   # EPSS > 0.70
EPSS_MEDIUM_SCORE     = 10   # EPSS 0.40 - 0.70

UNPINNED_SCORE        = 5    # no exact version pinned

MAX_SCORE             = 100


# ── Risk label thresholds ──────────────────────────────────────────────────────

def get_risk_label(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 15:
        return "MEDIUM"
    else:
        return "LOW"


def get_risk_emoji(label: str) -> str:
    return {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🟢",
    }.get(label, "⚪")


# ── Scoring logic ──────────────────────────────────────────────────────────────

def score_package(enriched_package: dict) -> dict:
    """
    Score a single enriched package and return it with scoring details added.

    Adds a 'score' key to the package dict:
    {
        "total":      int,        # final capped score 0-100
        "label":      str,        # CRITICAL / HIGH / MEDIUM / LOW
        "emoji":      str,        # visual indicator
        "breakdown":  dict,       # points from each factor
        "reasons":    list[str],  # human-readable explanation of what drove the score
    }
    """
    findings = enriched_package.get("findings", {})

    highest_cvss  = findings.get("highest_cvss", 0.0) or 0.0
    highest_epss  = findings.get("highest_epss", 0.0) or 0.0
    any_kev       = findings.get("any_kev", False)
    pinned        = enriched_package.get("pinned", False)

    breakdown = {
        "cvss":     0,
        "kev":      0,
        "epss":     0,
        "unpinned": 0,
    }
    reasons = []

    # ── CVSS points ────────────────────────────────────────────────────────────
    if highest_cvss >= 9.0:
        breakdown["cvss"] = CVSS_CRITICAL_SCORE
        reasons.append(f"Critical severity CVE (CVSS {highest_cvss})")
    elif highest_cvss >= 7.0:
        breakdown["cvss"] = CVSS_HIGH_SCORE
        reasons.append(f"High severity CVE (CVSS {highest_cvss})")
    elif highest_cvss >= 4.0:
        breakdown["cvss"] = CVSS_MEDIUM_SCORE
        reasons.append(f"Medium severity CVE (CVSS {highest_cvss})")

    # ── KEV points ─────────────────────────────────────────────────────────────
    if any_kev:
        breakdown["kev"] = KEV_SCORE
        kev_ids = findings.get("kev_hits", [])
        reasons.append(f"Actively exploited in the wild — in CISA KEV ({', '.join(kev_ids)})")

    # ── EPSS points ────────────────────────────────────────────────────────────
    if highest_epss > 0.70:
        breakdown["epss"] = EPSS_HIGH_SCORE
        reasons.append(f"High exploitation probability (EPSS {highest_epss:.0%})")
    elif highest_epss >= 0.40:
        breakdown["epss"] = EPSS_MEDIUM_SCORE
        reasons.append(f"Moderate exploitation probability (EPSS {highest_epss:.0%})")

    # ── Unpinned points ────────────────────────────────────────────────────────
    if not pinned:
        breakdown["unpinned"] = UNPINNED_SCORE
        reasons.append("Version not pinned — could silently upgrade to a vulnerable release")

    # ── Final score ────────────────────────────────────────────────────────────
    total = min(sum(breakdown.values()), MAX_SCORE)
    label = get_risk_label(total)
    emoji = get_risk_emoji(label)

    if not reasons:
        reasons.append("No significant risk signals detected")

    scored = dict(enriched_package)
    scored["score"] = {
        "total":     total,
        "label":     label,
        "emoji":     emoji,
        "breakdown": breakdown,
        "reasons":   reasons,
    }

    return scored


def score_all(enriched_packages: list) -> list:
    """
    Score all enriched packages and return them sorted by risk score
    (highest risk first).
    """
    scored = [score_package(p) for p in enriched_packages]
    scored.sort(key=lambda p: p["score"]["total"], reverse=True)
    return scored


# ── Display ────────────────────────────────────────────────────────────────────

def print_score_report(scored_packages: list) -> None:
    """Print a ranked risk report to the terminal."""

    print(f"\n{'='*60}")
    print(f"  AgentSCM — Risk Score Report")
    print(f"{'='*60}")
    print(f"  {'#':<4} {'PACKAGE':<25} {'SCORE':<8} {'LABEL':<10} CVEs")
    print(f"  {'-'*4} {'-'*25} {'-'*8} {'-'*10} {'-'*4}")

    for i, p in enumerate(scored_packages, 1):
        s = p["score"]
        f = p["findings"]
        vs = p.get('version_spec') or ''
        ver = p.get('version') or ''
        version = f"{vs}{ver}".strip() or 'unpinned'
        name_ver = f"{p['name']} ({version})"
        cve_count = f["total_cves"]

        print(
            f"  {i:<4} {name_ver:<25} {s['total']:<8} "
            f"{s['emoji']} {s['label']:<8} {cve_count}"
        )

    print(f"\n{'='*60}")
    print(f"  Detailed Findings")
    print(f"{'='*60}")

    for p in scored_packages:
        s = p["score"]
        f = p["findings"]

        # Only show detail for packages with actual risk
        if s["total"] == 0:
            continue

        print(f"\n  {s['emoji']} {p['name'].upper()} — {s['label']} (score: {s['total']}/100)")
        print(f"  {'─'*50}")

        print(f"  Why flagged:")
        for reason in s["reasons"]:
            print(f"    • {reason}")

        print(f"\n  Score breakdown:")
        for factor, points in s["score"]["breakdown"].items() if False else s["breakdown"].items():
            if points > 0:
                print(f"    {factor:<12} +{points}")

        if f["cves"]:
            print(f"\n  Top CVEs:")
            # Show top 3 CVEs by CVSS score
            top_cves = sorted(f["cves"], key=lambda c: c.get("cvss_score") or 0, reverse=True)[:3]
            for cve in top_cves:
                kev_tag = " ⚠ KEV" if cve.get("in_kev") else ""
                epss = cve.get("epss_score", 0.0)
                print(f"    {cve['cve_id']:<20} CVSS:{cve.get('cvss_score','?'):<6} EPSS:{epss:.2f}{kev_tag}")

    print()


# ── Quick test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Test scorer with mock enriched data — no API calls needed
    mock_packages = [
        {
            "name": "requests",
            "version": "2.28.1",
            "version_spec": "==",
            "pinned": True,
            "findings": {
                "total_cves": 2,
                "any_kev": False,
                "kev_hits": [],
                "highest_cvss": 7.5,
                "highest_epss": 0.55,
                "cves": [
                    {
                        "cve_id": "CVE-2023-32681",
                        "cvss_score": 7.5,
                        "cvss_severity": "HIGH",
                        "epss_score": 0.55,
                        "in_kev": False,
                        "description": "Requests forwards proxy-authorization headers to destination servers."
                    }
                ],
            }
        },
        {
            "name": "pillow",
            "version": "9.0.0",
            "version_spec": "==",
            "pinned": True,
            "findings": {
                "total_cves": 3,
                "any_kev": True,
                "kev_hits": ["CVE-2022-22816"],
                "highest_cvss": 9.8,
                "highest_epss": 0.82,
                "cves": [
                    {
                        "cve_id": "CVE-2022-22816",
                        "cvss_score": 9.8,
                        "cvss_severity": "CRITICAL",
                        "epss_score": 0.82,
                        "in_kev": True,
                        "description": "path_getbbox in path.c in Pillow has a buffer over-read."
                    }
                ],
            }
        },
        {
            "name": "numpy",
            "version": None,
            "version_spec": None,
            "pinned": False,
            "findings": {
                "total_cves": 0,
                "any_kev": False,
                "kev_hits": [],
                "highest_cvss": 0.0,
                "highest_epss": 0.0,
                "cves": [],
            }
        },
    ]

    scored = score_all(mock_packages)
    print_score_report(scored)
