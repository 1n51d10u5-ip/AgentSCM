# AgentSCM 🔍

An agentic open-source dependency threat detection platform that analyzes your Python project's dependencies, correlates them with live vulnerability intelligence, and prioritizes the ones that need immediate action.

## What it does

- Parses your `requirements.txt` into a clean package inventory
- Enriches each package with CVE data (NVD), active exploitation status (CISA KEV), and exploit likelihood (EPSS)
- Scores risk using severity + exploitation context + dependency signals
- Generates analyst-ready findings with remediation recommendations
- Displays results in an interactive dashboard

## Why it matters

Most vulnerability scanners dump every CVE and leave us to figure out what matters. This tool prioritizes a CVE that's being actively exploited and has a 90% EPSS score is not the same as a theoretical low-severity issue from 3 years ago.

## Tech stack

- Python 3.11+
- NVD API (CVE data)
- CISA KEV (active exploitation watchlist)
- FIRST EPSS API (exploit probability scoring)
- Streamlit (dashboard)


## Project structure

```
AgentSCM/
├── src/
│   ├── parser.py        # Stage 1: Parse requirements.txt
│   ├── enricher.py      # Stage 2: Fetch CVE/KEV/EPSS data
│   ├── scorer.py        # Stage 3: Risk scoring and ranking
│   ├── pipeline.py      # Stage 4: Wires all stages, main entry point
│   └── dashboard.py     # Stage 5: Streamlit UI        [coming soon]
├── data/
│   └── samples/         # Sample requirements files for testing
├── tests/
├── .env                 # Your API keys — never committed
└── requirements.txt
```

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
 
  AgentSCM — Recommended Actions
  ────────────────────────────────────────────────────────────
  🔴 CRITICAL — Patch or mitigate immediately
     • pillow
 
  🟡 MEDIUM — Review and plan remediation
     • requests
 
  🟢 LOW — Monitor, no immediate action
     • django
     • numpy
```

## Roadmap
 
- [x] Stage 1: Parser — requirements.txt ingestion and normalization
- [x] Stage 2: Enricher — NVD + KEV + EPSS integration
- [x] Stage 3: Scorer — rule-based risk prioritization and ranking
- [x] Stage 4: Pipeline — full end-to-end wiring with action summary
- [ ] Stage 5: Dashboard — Streamlit UI

## Setup

```bash
git clone https://github.com/1n51d10u5-ip/AgentSCM
cd AgentSCM
pip install -r requirements.txt
python src/parser.py requirements.txt
```

Create a `.env` file in the project root:
```
NVD_API_KEY=your-key-here
```

Get a free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key

Add the '.env' to '.gitignore'

## Usage
 
Run the full pipeline on any `requirements.txt`:
 
```bash
python src/pipeline.py /path/to/your/project/requirements.txt
```
 
Results are printed to terminal and saved to `data/results.json`.
---

Built as a project demonstrating supply-chain security analysis, threat intelligence enrichment, and detection engineering principles.
