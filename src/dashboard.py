"""
dashboard.py
------------
Stage 5: Streamlit dashboard for AgentSCM.

Run with:
    streamlit run src/dashboard.py

Features:
    - Upload requirements.txt
    - Run full pipeline (parse -> enrich -> score)
    - Risk summary metrics
    - Ranked risk table
    - Per-package detail expander
    - Download results as JSON
"""

import os
import sys
import json
import tempfile
import streamlit as st
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.parser import parse_requirements
from src.enricher import EnricherConfig, enrich_all
from src.scorer import score_all
from src.pipeline import print_action_summary, save_results, detect_and_parse
from src.remediation import add_remediation

load_dotenv()

# ── Page config ────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="AgentSCM",
    page_icon="🔍",
    layout="wide",
)

# ── Styles ─────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
    .risk-critical { color: #e63946; font-weight: 600; }
    .risk-high     { color: #f4845f; font-weight: 600; }
    .risk-medium   { color: #f4a261; font-weight: 600; }
    .risk-low      { color: #52b788; font-weight: 600; }
    .metric-box    { background: #f8f9fa; border-radius: 8px; padding: 1rem; text-align: center; }
    div[data-testid="stExpander"] { border: 1px solid #eee; border-radius: 8px; margin-bottom: 0.5rem; }
</style>
""", unsafe_allow_html=True)

# ── Header ─────────────────────────────────────────────────────────────────────

st.title("🔍 AgentSCM")
st.caption("Agentic Supply Chain Monitor — dependency risk analysis powered by NVD, CISA KEV, and EPSS")
st.divider()

# ── Sidebar ────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("⚙️ Configuration")

    nvd_key = os.environ.get("NVD_API_KEY", "")
    if nvd_key:
        st.success("NVD API key loaded ✓")
    else:
        nvd_key = st.text_input(
            "NVD API key (optional)",
            type="password",
            help="Without a key, NVD requests are rate-limited to 5/30s. Get a free key at nvd.nist.gov/developers/request-an-api-key"
        )
        if not nvd_key:
            st.warning("No NVD key — slow mode")

    vulncheck_key = os.environ.get("VULNCHECK_API_KEY", "")
    if vulncheck_key:
        st.success("VulnCheck NVD++ fallback enabled ✓")
    else:
        vulncheck_key = st.text_input(
            "VulnCheck API key (recommended)",
            type="password",
            help="Free at vulncheck.com — enables reliable NVD++ fallback when NIST NVD is down (which is often)."
        )
        if not vulncheck_key:
            st.info("Add VulnCheck key for NVD fallback")

    st.divider()
    st.markdown("**Data sources**")
    st.markdown("- 🔵 [NVD](https://nvd.nist.gov) — CVE database")
    st.markdown("- 🔴 [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — active exploitation")
    st.markdown("- 🟡 [FIRST EPSS](https://www.first.org/epss) — exploit probability")

    st.divider()
    st.markdown("**Risk score legend**")
    st.markdown("🔴 CRITICAL — 70–100")
    st.markdown("🟠 HIGH — 40–69")
    st.markdown("🟡 MEDIUM — 15–39")
    st.markdown("🟢 LOW — 0–14")

# ── File upload ────────────────────────────────────────────────────────────────

st.subheader("📂 Upload your dependency file")

col1, col2 = st.columns([2, 1])

with col1:
    uploaded_file = st.file_uploader(
        "Drop your requirements.txt or package-lock.json here",
        type=["txt", "json"],
        help="Supports Python (requirements.txt) and npm (package-lock.json). "
             "For npm, lockfile v2/v3 (npm 7+) required for accurate results."
    )

with col2:
    st.markdown("**Don't have one handy?**")
    use_sample = st.button("▶ Run with sample (Python)", width="stretch")
    use_sample_npm = st.button("▶ Run with sample (npm)", width="stretch")

# ── Pipeline execution ─────────────────────────────────────────────────────────

def run_pipeline(file_path: str, nvd_api_key: str, vulncheck_api_key: str = "") -> tuple:
    """Run full AgentSCM pipeline and return scored packages + metadata."""
    packages, skipped, ecosystem_label = detect_and_parse(file_path)
    config = EnricherConfig(
        nvd_api_key=nvd_api_key,
        vulncheck_api_key=vulncheck_api_key,
    )
    enriched = enrich_all(packages, config)
    scored = score_all(enriched)
    scored = add_remediation(scored)
    return scored, len(skipped), ecosystem_label


def render_results(scored: list, skipped_count: int) -> None:
    """Render the full results UI."""

    st.divider()
    st.subheader("📊 Risk Summary")

    # ── Summary metrics ────────────────────────────────────────────────────────
    total     = len(scored)
    critical  = sum(1 for p in scored if p["score"]["label"] == "CRITICAL")
    high      = sum(1 for p in scored if p["score"]["label"] == "HIGH")
    medium    = sum(1 for p in scored if p["score"]["label"] == "MEDIUM")
    low       = sum(1 for p in scored if p["score"]["label"] == "LOW")
    kev_count = sum(1 for p in scored if p["findings"]["any_kev"])

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Total packages", total)
    m2.metric("🔴 Critical",    critical,  delta=f"{critical} urgent"  if critical else None, delta_color="inverse")
    m3.metric("🟠 High",        high,      delta=f"{high} urgent"      if high     else None, delta_color="inverse")
    m4.metric("🟡 Medium",      medium)
    m5.metric("🟢 Low",         low)
    m6.metric("⚠️ In KEV",      kev_count, delta="active exploits"     if kev_count else None, delta_color="inverse")

    # ── Action summary ─────────────────────────────────────────────────────────
    if critical or high:
        st.divider()
        st.subheader("🚨 Immediate Actions Required")

        action_packages = [p for p in scored if p["score"]["label"] in ("CRITICAL", "HIGH")]
        for p in action_packages:
            s = p["score"]
            label_color = "🔴" if s["label"] == "CRITICAL" else "🟠"
            st.error(
                f"{label_color} **{p['name']}** — Score {s['total']}/100 · "
                f"{s['label']} · {p['findings']['total_cves']} CVE(s)"
                + (" · ⚠️ In CISA KEV" if p["findings"]["any_kev"] else "")
            )

    # ── Full ranked table ──────────────────────────────────────────────────────
    st.divider()
    st.subheader("📋 Full Risk Ranking")

    table_data = []
    for i, p in enumerate(scored, 1):
        s = p["score"]
        f = p["findings"]
        version = f"{p.get('version_spec','') or ''}{p.get('version','') or ''}".strip() or "unpinned"
        kev = "⚠️ Yes" if f["any_kev"] else "—"
        rem = p.get("remediation", {})
        table_data.append({
            "#":           i,
            "Package":     p["name"],
            "Version":     version,
            "Score":       s["total"],
            "Risk":        f"{s['emoji']} {s['label']}",
            "CVEs":        f["total_cves"],
            "CVSS":        f["highest_cvss"] if f["highest_cvss"] else None,
            "EPSS":        f"{f['highest_epss']:.0%}" if f["highest_epss"] else "—",
            "In KEV":      kev,
            "Pinned":      "✓" if p.get("pinned") else "✗",
            "Action":      rem.get("action", "—"),
            "Fix":         rem.get("suggestion", "—"),
        })

    st.dataframe(
        table_data,
        width="stretch",
        hide_index=True,
        column_config={
            "Score": st.column_config.ProgressColumn(
                "Score",
                min_value=0,
                max_value=100,
                format="%d",
            ),
        }
    )

    # ── Per-package detail ─────────────────────────────────────────────────────
    st.divider()
    st.subheader("🔎 Package Details")

    at_risk = [p for p in scored if p["score"]["total"] > 0]
    clean   = [p for p in scored if p["score"]["total"] == 0]

    if at_risk:
        st.markdown("**Packages with findings:**")
        for p in at_risk:
            s = p["score"]
            f = p["findings"]
            version = f"{p.get('version_spec','') or ''}{p.get('version','') or ''}".strip() or "unpinned"

            with st.expander(f"{s['emoji']} {p['name']} ({version}) — {s['label']} · Score {s['total']}/100"):

                col_l, col_r = st.columns(2)

                with col_l:
                    st.markdown("**Why flagged:**")
                    for reason in s["reasons"]:
                        st.markdown(f"- {reason}")

                with col_r:
                    st.markdown("**Score breakdown:**")
                    breakdown = s["breakdown"]
                    for factor, points in breakdown.items():
                        if points > 0:
                            st.markdown(f"- `{factor}`: +{points} pts")

                rem = p.get("remediation", {})
                if rem and rem.get("action") != "NO ACTION":
                    st.markdown("**Remediation:**")
                    st.info(
                        f"**{rem['action']}** — {rem['reason']}\n\n"
                        f"```\n{rem['suggestion']}\n```"
                        + (f"\n\nLatest available: `{rem['latest']}`" if rem.get("latest") else "")
                    )

                if f["cves"]:
                    st.markdown("**Top CVEs:**")
                    cve_rows = []
                    top_cves = sorted(f["cves"], key=lambda c: c.get("cvss_score") or 0, reverse=True)[:5]
                    for cve in top_cves:
                        cve_rows.append({
                            "CVE ID":      cve["cve_id"],
                            "CVSS":        cve.get("cvss_score", "—"),
                            "Severity":    cve.get("cvss_severity", "—"),
                            "EPSS":        f"{cve.get('epss_score', 0):.0%}",
                            "In KEV":      "⚠️ Yes" if cve.get("in_kev") else "—",
                            "Published":   cve.get("published_date", "—"),
                        })
                    st.dataframe(cve_rows, width="stretch", hide_index=True)

                    st.markdown("**Description:**")
                    st.caption(top_cves[0].get("description", "No description available."))

    if clean:
        with st.expander(f"🟢 {len(clean)} clean package(s) — no findings"):
            for p in clean:
                version = f"{p.get('version_spec','') or ''}{p.get('version','') or ''}".strip() or "unpinned"
                st.markdown(f"- `{p['name']}` ({version})")

    # ── Download ───────────────────────────────────────────────────────────────
    st.divider()
    st.subheader("💾 Export Results")

    export = []
    for p in scored:
        export.append({
            "name":     p["name"],
            "version":  p.get("version"),
            "pinned":   p.get("pinned"),
            "score":    p["score"],
            "findings": {
                "total_cves":   p["findings"]["total_cves"],
                "any_kev":      p["findings"]["any_kev"],
                "kev_hits":     p["findings"]["kev_hits"],
                "highest_cvss": p["findings"]["highest_cvss"],
                "highest_epss": p["findings"]["highest_epss"],
                "cves":         p["findings"]["cves"],
            }
        })

    st.download_button(
        label="⬇️ Download full report (JSON)",
        data=json.dumps(export, indent=2),
        file_name="agentscm_report.json",
        mime="application/json",
        width="stretch",
    )

    if skipped_count:
        st.caption(f"ℹ️ {skipped_count} line(s) skipped during parsing (git URLs, editable installs, or complex version specs).")


# ── Main flow ──────────────────────────────────────────────────────────────────

if uploaded_file or use_sample or use_sample_npm:
    with st.spinner("Running AgentSCM pipeline — fetching CVE, KEV, and EPSS data..."):
        try:
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

            if use_sample:
                file_path = os.path.join(project_root, "data", "samples", "requirements.txt")
            elif use_sample_npm:
                file_path = os.path.join(project_root, "data", "samples", "package-lock.json")
            else:
                # Write uploaded file to a temp dir, preserving the original
                # filename — detect_and_parse() routes based on exact name
                # (e.g. "package-lock.json" vs "requirements.txt")
                tmp_dir = tempfile.mkdtemp()
                file_path = os.path.join(tmp_dir, uploaded_file.name)
                with open(file_path, "wb") as f:
                    f.write(uploaded_file.read())

            scored, skipped_count, ecosystem_label = run_pipeline(
                file_path,
                nvd_api_key=nvd_key,
                vulncheck_api_key=vulncheck_key,
            )
            st.caption(f"📦 Detected: **{ecosystem_label}**")
            render_results(scored, skipped_count)

        except (FileNotFoundError, ValueError) as e:
            st.error(f"Error: {e}")
        except Exception as e:
            st.error(f"Unexpected error: {e}")
            st.exception(e)

else:
    # Landing state — show instructions
    st.info("👆 Upload a requirements.txt or package-lock.json above, or click 'Run with sample file' to see a demo.")

    st.markdown("""
    **What AgentSCM checks for:**

    | Signal | Source | What it means |
    |---|---|---|
    | CVEs | NVD | Known vulnerabilities in this package version |
    | Active exploitation | CISA KEV | Vulnerability being exploited in the wild right now |
    | Exploit probability | FIRST EPSS | Likelihood of exploitation in the next 30 days |
    | Version pinning | requirements.txt / lockfile | Unpinned packages can silently upgrade to vulnerable versions |

    **Supported ecosystems:**

    | Ecosystem | File | Notes |
    |---|---|---|
    | Python | `requirements.txt` | Pinned (`==`) and unpinned packages |
    | npm | `package-lock.json` | Lockfile v2/v3 (npm 7+) — exact resolved versions, direct + transitive |
    | npm | `package.json` | Fallback — direct dependencies only, version ranges (less precise) |
    """)