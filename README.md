# Dependency Threat Monitor 🔍

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
- CISA KEV (active exploitation)
- FIRST EPSS API (exploit probability)
- Streamlit (dashboard)

<!--
## Project structure

```
AgentSCM/
├── src/
│   ├── parser.py        # Stage 1: Parse requirements.txt
│   ├── enricher.py      # Stage 2: Fetch CVE/KEV/EPSS data
│   ├── scorer.py        # Stage 3: Risk scoring logic
│   ├── reporter.py      # Stage 4: Findings and recommendations
│   └── dashboard.py     # Stage 5: Streamlit UI
├── data/
│   └── samples/         # Sample requirements files for testing
├── tests/
└── docs/
```
-->

## Roadmap

- [x] Stage 1: Parser — requirements.txt ingestion and normalization
- [ ] Stage 2: Enricher — NVD + KEV + EPSS integration
- [ ] Stage 3: Scorer — rule-based risk prioritization
- [ ] Stage 4: Reporter — analyst findings and recommendations
- [ ] Stage 5: Dashboard — Streamlit UI

## Setup

```bash
git clone https://github.com/1n51d10u5-ip/AgentSCM
cd AgentSCM
pip install -r requirements.txt
python src/parser.py data/samples/requirements.txt
```

---

Built as a portfolio project demonstrating supply-chain security analysis, threat intelligence enrichment, and detection engineering principles.
