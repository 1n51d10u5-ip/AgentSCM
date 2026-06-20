# AgentSCM 🔍

![Supply Chain Scan](https://github.com/1n51d10u5-ip/AgentSCM/actions/workflows/supply-chain-scan.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

An agentic supply chain threat detection platform that analyzes your project's dependencies— Python or npm, and correlates them with live vulnerability intelligence, and prioritizes the ones that need immediate action.

## What it does

- Parses `requirements.txt` (Python) or `package-lock.json` (npm) into a clean package inventory
- Enriches each package with CVE data (OSV), active exploitation status (CISA KEV), and exploit likelihood (EPSS)
- Scores and ranks risk using severity + exploitation context + pinning status
- Suggests corresponding remediation — exact upgrade version pulled from PyPI or npm registry
- Generates analyst-ready findings with recommended actions
- Displays results in an interactive dashboard

## Why it matters

Most vulnerability scanners dump every CVE and leave us to figure out what matters. This tool prioritizes a CVE that's being actively exploited and has a 90% EPSS score is not the same as a theoretical low-severity issue from long time ago.

## Dashboard

![AgentSCM Dashboard](docs/dashboard_screenshot_1.png)
 
## Tech stack

- Python 3.11+
- OSV API (CVE data — no key required)
- CISA KEV (active exploitation watchlist)
- FIRST EPSS API (exploit probability scoring)
- PyPI API (Python remediation — latest safe version)
- npm Registry API (npm remediation — latest safe version)
- Streamlit (dashboard)


## Project structure

```
AgentSCM/
├── src/
│   ├── parser.py        # Stage 1: Parse requirements.txt
│   ├── parser_npm.py    # Stage 1: Parse package-lock.json (npm)
│   ├── enricher.py      # Stage 2: Fetch CVE/KEV/EPSS data
│   ├── scorer.py        # Stage 3: Risk scoring and ranking
│   ├── remediation.py   # Stage 4: PyPI/npm latest version + remediation suggestions
│   ├── pipeline.py      # Stage 5: Main entry point- wires all stages
│   └── dashboard.py     # Stage 6: Streamlit dashboard
├── data/
│   └── samples/         # Sample requirements.txt and package-lock.json for testing
├── .github/
│   └── workflows/       # GitHub Actions CI — supply chain scan on every PR
├── docs/
└── .env                 # Your API keys — never committed

```

## Setup

```bash
git clone https://github.com/1n51d10u5-ip/AgentSCM
cd AgentSCM
pip install -r requirements.txt #To install this program's dependencies

```

No API keys required to run. Optionally, add a VulnCheck token to your `.env` for KEV fallback if CISA's feed is unavailable:
 
```
VULNCHECK_API_KEY=your-token-here
```
 
Get a free VulnCheck token at: https://vulncheck.com

## Usage
 
Run the full pipeline — AgentSCM auto-detects the file type:
 
```bash
# Python projects
python src/pipeline.py data/samples/requirements.txt
python src/pipeline.py /path/to/your/project/requirements.txt
 
# npm projects
python src/pipeline.py data/samples/package-lock.json
python src/pipeline.py /path/to/your/project/package-lock.json
```
 
Results are printed to terminal and saved to `data/results.json`.

Or launch the interactive dashboard:
 
```bash
streamlit run src/dashboard.py
```
 
Then open http://localhost:8501 in your browser. Upload any `requirements.txt` or click "Run with sample file" to see live demo.

## Sample output
 
```
  AgentSCM — Risk Score Report
  ────────────────────────────────────────────────────────────
  #    PACKAGE                   SCORE    LABEL      CVEs
  ---- ------------------------- -------- ---------- ----
  1    pillow (==9.0.0)          90       🔴 CRITICAL  3
  2    requests (==2.28.1)       35       🟡 MEDIUM    1
  3    django (==3.2.0)          10       🟢 LOW       2
  4    numpy (unpinned)           5       🟢 LOW       0
 
  AgentSCM — Remediation Report
  ────────────────────────────────────────────────────────────
  🔴 pillow
     Action  : UPGRADE IMMEDIATELY
     Reason  : Actively exploited vulnerability (CISA KEV)
     Fix     : pillow==12.2.0
 
  🟠 django
     Action  : UPGRADE
     Reason  : Critical severity CVE and newer version available
     Fix     : django==6.0.6
```
 
npm projects produce the same output with `@` version syntax (e.g. `axios@1.17.0`).

## Risk scoring

Each package is scored 0–100 based on four signals:

| Signal | Points |
|---|---|
| Critical CVE (CVSS 9–10) | 40 |
| High CVE (CVSS 7–8.9) | 25 |
| Medium CVE (CVSS 4–6.9) | 10 |
| In CISA KEV (actively exploited) | +30 |
| High EPSS >70% | +20 |
| Moderate EPSS 40–70% | +10 |
| Version not pinned | +5 |

Scores map to: 🔴 CRITICAL (70+) · 🟠 HIGH (40–69) · 🟡 MEDIUM (15–39) · 🟢 LOW (0–14)

---

Built as a project demonstrating supply-chain security analysis, threat intelligence enrichment, and detection engineering principles.


## Feature Roadmap 
 
### 🔵 Must have
| Feature | Reason |
|---|---|
| Streamlit dashboard | ✅ Done |
| npm / package-lock.json support | ✅ Done — ecosystem-aware enrichment + npm registry remediation |
| Remediation suggestions per package | ✅ Done — PyPI/npm latest version lookup with action per package |
| Exportable JSON report | ✅ Done |
| GitHub Actions CI integration | ✅ Done |
 
### 🟢 Should have
| Feature | Reason |
|---|---|
| `poetry.lock` support | Most modern Python projects support |
| Dependency graph view | Visualize direct vs transitive risk paths |
| CycloneDX SBOM input | Formal SBOM support for enterprise and DevSecOps credibility |
 
### 🟡 Could have
| Feature | Reason |
|---|---|
| Fresh exploit signal ingestion | Paste a CVE or advisory and checks if packages are affected |
| LLM-generated analyst brief | Natural language summary of top risks and recommended actions |
| Package maintainer health signals | Last release date with contributor count and staleness risk |
| Typosquatting detection | Flag packages with names suspiciously similar to popular libraries |
| Live Twitter/X scraping | Brittle and API-restricted; manual signal input covers the concept cleanly |
| Dependency graph view | Visualize direct vs transitive risk paths |
| CycloneDX SBOM input | Formal SBOM support for enterprise and DevSecOps credibility |

### ⚫ Won't have
| Feature | Reason |
|---|---|
| ML-based scoring | Rule-based is explainable and sufficient; ML adds complexity without value here |
| Auto-patching / PR creation | A step out into remediation automation |
| Multi-tenant / SaaS mode | In case someday envision this as product |