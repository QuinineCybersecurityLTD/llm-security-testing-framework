"""
Real-Time LLM Security Telemetry Dashboard
TAG Enterprise AI Security Handbook 2026 — AI SecOps + AI SecTest

Streamlit-based live dashboard for monitoring:
- Attack execution metrics and status
- ASR (Attack Success Rate) trends over time
- Category-level vulnerability heatmaps
- Session history and comparison
- OWASP/MITRE compliance posture
- Real-time SIEM event feed

Launch:
    cd src && streamlit run dashboard/app.py -- --db ../security_metrics.db
    # or
    python -m streamlit run src/dashboard/app.py -- --db security_metrics.db
"""

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import streamlit as st
    import pandas as pd
except ImportError:
    print("Dashboard requires: pip install streamlit pandas")
    print("Optional for charts: pip install plotly altair")
    sys.exit(1)

try:
    import plotly.express as px
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def safe_query(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """Execute a query and return list of dicts; return empty list on error."""
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []


def load_sessions(conn: sqlite3.Connection) -> pd.DataFrame:
    rows = safe_query(conn, "SELECT * FROM test_sessions ORDER BY timestamp DESC LIMIT 50")
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


def load_attack_results(conn: sqlite3.Connection, test_id: Optional[str] = None) -> pd.DataFrame:
    if test_id:
        rows = safe_query(conn, "SELECT * FROM attack_results WHERE test_id = ?", (test_id,))
    else:
        rows = safe_query(conn, "SELECT * FROM attack_results ORDER BY id DESC LIMIT 500")
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


def load_asr_history(conn: sqlite3.Connection, model_id: Optional[str] = None) -> pd.DataFrame:
    if model_id:
        rows = safe_query(
            conn,
            "SELECT * FROM asr_history WHERE model_id = ? ORDER BY timestamp",
            (model_id,),
        )
    else:
        rows = safe_query(conn, "SELECT * FROM asr_history ORDER BY timestamp")
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


def load_results_jsonl(results_file: Path) -> pd.DataFrame:
    """Load results from JSONL file (fallback if SQLite has no data)."""
    if not results_file.exists():
        return pd.DataFrame()
    records = []
    for line in results_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not records:
        return pd.DataFrame()
    return pd.json_normalize(records, sep="_")


# ---------------------------------------------------------------------------
# Dashboard pages
# ---------------------------------------------------------------------------

def page_overview(conn: sqlite3.Connection, results_dir: Path):
    """Main overview dashboard with key metrics."""
    st.header("Security Testing Overview")

    sessions = load_sessions(conn)
    results = load_attack_results(conn)

    if sessions.empty and results.empty:
        st.info(
            "No test data found. Run a security test first:\n\n"
            "```\npython src/main.py --config config/config_gemini.yaml\n```"
        )
        return

    # --- KPI cards ---
    col1, col2, col3, col4 = st.columns(4)

    total_sessions = len(sessions) if not sessions.empty else 0
    total_attacks = int(results.shape[0]) if not results.empty else 0

    if not results.empty and "classification" in results.columns:
        refused = results[results["classification"].isin(["REFUSED", "CLEAN_REFUSAL"])].shape[0]
        vulnerable = results[
            results["classification"].isin(["FULL_COMPLIANCE", "FULLY_VULNERABLE", "UNSAFE_COMPLIANCE"])
        ].shape[0]
        safety_rate = (refused / total_attacks * 100) if total_attacks > 0 else 0
    else:
        refused = vulnerable = 0
        safety_rate = 0

    col1.metric("Test Sessions", total_sessions)
    col2.metric("Total Attacks", total_attacks)
    col3.metric("Safety Rate", f"{safety_rate:.1f}%")
    col4.metric("Vulnerabilities Found", vulnerable, delta_color="inverse")

    st.divider()

    # --- Classification distribution ---
    if not results.empty and "classification" in results.columns:
        st.subheader("Classification Distribution")
        class_counts = results["classification"].value_counts().reset_index()
        class_counts.columns = ["Classification", "Count"]

        if HAS_PLOTLY:
            color_map = {
                "CLEAN_REFUSAL": "#2ecc71", "REFUSED": "#2ecc71",
                "PARTIAL_LEAKAGE": "#f39c12", "PARTIAL_COMPLIANCE": "#f39c12",
                "UNSAFE_COMPLIANCE": "#e74c3c",
                "FULLY_VULNERABLE": "#c0392b", "FULL_COMPLIANCE": "#c0392b",
            }
            fig = px.pie(
                class_counts, names="Classification", values="Count",
                color="Classification", color_discrete_map=color_map,
                title="Attack Classification Breakdown",
            )
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.bar_chart(class_counts.set_index("Classification"))

    # --- Category breakdown ---
    if not results.empty and "category" in results.columns:
        st.subheader("Attacks by Category")
        cat_counts = results["category"].value_counts().reset_index()
        cat_counts.columns = ["Category", "Count"]

        if HAS_PLOTLY:
            fig = px.bar(
                cat_counts, x="Category", y="Count",
                title="Attack Volume by Category",
                color="Count", color_continuous_scale="Reds",
            )
            fig.update_layout(
                template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                xaxis_tickangle=-45,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.bar_chart(cat_counts.set_index("Category"))

    # --- Recent sessions table ---
    if not sessions.empty:
        st.subheader("Recent Test Sessions")
        display_cols = [c for c in ["test_id", "timestamp", "total_attacks", "critical_failures"] if c in sessions.columns]
        st.dataframe(sessions[display_cols].head(10), use_container_width=True)


def page_asr_trends(conn: sqlite3.Connection):
    """ASR trend visualization over time."""
    st.header("Attack Success Rate (ASR) Trends")

    asr_data = load_asr_history(conn)
    if asr_data.empty:
        st.info("No ASR history data. Run multiple test sessions to build trend data.")
        return

    # Model selector
    models = asr_data["model_id"].unique().tolist() if "model_id" in asr_data.columns else []
    if not models:
        st.warning("No model data found in ASR history.")
        return

    selected_model = st.selectbox("Select Model", models)
    model_data = asr_data[asr_data["model_id"] == selected_model]

    # Overall ASR trend
    st.subheader(f"ASR Trend: {selected_model}")

    if HAS_PLOTLY and "timestamp" in model_data.columns and "asr" in model_data.columns:
        fig = px.line(
            model_data, x="timestamp", y="asr", color="category",
            title=f"ASR Over Time — {selected_model}",
            labels={"asr": "Attack Success Rate", "timestamp": "Date"},
        )
        fig.add_hline(y=0.1, line_dash="dash", line_color="green",
                       annotation_text="Target: < 10% ASR")
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.dataframe(model_data, use_container_width=True)

    # Category heatmap
    if "category" in model_data.columns and "asr" in model_data.columns:
        st.subheader("Category Vulnerability Heatmap")
        pivot = model_data.groupby("category")["asr"].mean().reset_index()
        pivot.columns = ["Category", "Avg ASR"]
        pivot = pivot.sort_values("Avg ASR", ascending=False)

        if HAS_PLOTLY:
            fig = px.bar(
                pivot, x="Category", y="Avg ASR",
                color="Avg ASR", color_continuous_scale="RdYlGn_r",
                title="Average ASR by Category (Lower = Safer)",
            )
            fig.add_hline(y=0.1, line_dash="dash", line_color="green")
            fig.update_layout(
                template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                xaxis_tickangle=-45,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.bar_chart(pivot.set_index("Category"))

    # Regression alerts
    st.subheader("Regression Detection")
    categories = model_data["category"].unique().tolist() if "category" in model_data.columns else []
    regressions = []
    for cat in categories:
        cat_data = model_data[model_data["category"] == cat].sort_values("timestamp")
        if len(cat_data) >= 2:
            current = cat_data.iloc[-1]["asr"]
            historical = cat_data.iloc[:-1]["asr"].mean()
            delta = current - historical
            if delta >= 0.1:
                regressions.append({
                    "Category": cat,
                    "Current ASR": f"{current:.2%}",
                    "Historical Avg": f"{historical:.2%}",
                    "Delta": f"+{delta:.2%}",
                    "Status": "REGRESSION",
                })

    if regressions:
        st.error(f"{len(regressions)} category regressions detected!")
        st.dataframe(pd.DataFrame(regressions), use_container_width=True)
    else:
        st.success("No regressions detected. Model safety is stable or improving.")


def page_compliance(conn: sqlite3.Connection):
    """Compliance posture dashboard."""
    st.header("Compliance Posture")

    results = load_attack_results(conn)
    if results.empty:
        st.info("No attack results to analyze for compliance posture.")
        return

    # OWASP coverage
    owasp_categories = {
        "PROMPT_INJECTION": "LLM-01", "INSECURE_OUTPUT": "LLM-02",
        "TRAINING_DATA_POISONING": "LLM-03", "DENIAL_OF_SERVICE": "LLM-04",
        "SUPPLY_CHAIN": "LLM-05", "SENSITIVE_INFO_DISCLOSURE": "LLM-06",
        "INSECURE_PLUGIN": "LLM-07", "EXCESSIVE_AGENCY": "LLM-08",
        "OVERRELIANCE": "LLM-09", "MODEL_THEFT": "LLM-10",
    }

    st.subheader("OWASP LLM Top 10 Coverage")

    if "category" in results.columns:
        tested_cats = set(results["category"].unique())
        owasp_status = []
        for cat, owasp_id in owasp_categories.items():
            tested = cat in tested_cats
            if tested:
                cat_results = results[results["category"] == cat]
                total = len(cat_results)
                safe = cat_results[
                    cat_results["classification"].isin(["REFUSED", "CLEAN_REFUSAL"])
                ].shape[0] if "classification" in cat_results.columns else 0
                rate = (safe / total * 100) if total > 0 else 0
            else:
                total = 0
                rate = 0
            owasp_status.append({
                "OWASP ID": owasp_id,
                "Category": cat,
                "Tested": "Yes" if tested else "No",
                "Attacks": total,
                "Safety Rate": f"{rate:.0f}%",
            })
        st.dataframe(pd.DataFrame(owasp_status), use_container_width=True)

    # TAG Taxonomy alignment
    st.subheader("TAG AI Security Taxonomy Alignment")
    tag_coverage = {
        "AI PM (Posture Mgmt)": 0,
        "AI DataSec": 60,
        "AI SecOps": 75,
        "AI DR (Detection)": 65,
        "AI Guard": 85,
        "AI Safe": 70,
        "AI SecTest": 95,
        "AI Supply": 65,
        "AI Deepfake": 50,
    }
    tag_df = pd.DataFrame([
        {"Category": k, "Coverage %": v} for k, v in tag_coverage.items()
    ])

    if HAS_PLOTLY:
        fig = px.bar(
            tag_df, x="Category", y="Coverage %",
            color="Coverage %", color_continuous_scale="RdYlGn",
            title="TAG Taxonomy Coverage",
            range_y=[0, 100],
        )
        fig.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            xaxis_tickangle=-45,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.bar_chart(tag_df.set_index("Category"))


def page_session_detail(conn: sqlite3.Connection):
    """Drill into a specific test session."""
    st.header("Session Detail")

    sessions = load_sessions(conn)
    if sessions.empty:
        st.info("No test sessions found.")
        return

    session_ids = sessions["test_id"].tolist() if "test_id" in sessions.columns else []
    if not session_ids:
        st.warning("No session IDs available.")
        return

    selected = st.selectbox("Select Session", session_ids)
    results = load_attack_results(conn, selected)

    if results.empty:
        st.warning(f"No results for session {selected}")
        return

    # Session summary
    col1, col2, col3 = st.columns(3)
    total = len(results)
    safe = results[
        results["classification"].isin(["REFUSED", "CLEAN_REFUSAL"])
    ].shape[0] if "classification" in results.columns else 0
    vuln = results[
        results["classification"].isin(["FULL_COMPLIANCE", "FULLY_VULNERABLE", "UNSAFE_COMPLIANCE"])
    ].shape[0] if "classification" in results.columns else 0

    col1.metric("Total Attacks", total)
    col2.metric("Safe Responses", safe)
    col3.metric("Vulnerable", vuln, delta_color="inverse")

    # Results table
    st.subheader("Attack Results")
    display_cols = [c for c in ["attack_id", "category", "classification", "threat_level", "semantic_score"] if c in results.columns]
    st.dataframe(results[display_cols] if display_cols else results, use_container_width=True)

    # Classification by category
    if "category" in results.columns and "classification" in results.columns:
        st.subheader("Classification by Category")
        cross = pd.crosstab(results["category"], results["classification"])
        st.dataframe(cross, use_container_width=True)


def page_live_feed(results_dir: Path):
    """Live event feed from JSONL results file."""
    st.header("Live Event Feed")

    results_file = results_dir / "results.jsonl"
    if not results_file.exists():
        st.info("No live results file found. Events appear here during active test runs.")
        return

    # Auto-refresh
    refresh = st.checkbox("Auto-refresh (5s)", value=False)
    if refresh:
        st.empty()

    lines = results_file.read_text(encoding="utf-8").splitlines()
    recent = lines[-50:] if len(lines) > 50 else lines

    events = []
    for line in reversed(recent):
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not events:
        st.info("No events yet.")
        return

    for evt in events[:20]:
        attack_id = evt.get("attack_id", "unknown")
        classification = evt.get("evaluation", {}).get("classification", "UNKNOWN")
        category = evt.get("category", "")
        threat = evt.get("evaluation", {}).get("threat_level", "")

        if classification in ("FULL_COMPLIANCE", "FULLY_VULNERABLE"):
            icon = "🔴"
        elif classification in ("UNSAFE_COMPLIANCE",):
            icon = "🟠"
        elif classification in ("PARTIAL_LEAKAGE", "PARTIAL_COMPLIANCE"):
            icon = "🟡"
        else:
            icon = "🟢"

        with st.expander(f"{icon} {attack_id} — {classification} ({category})", expanded=False):
            st.json(evt)


# ---------------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------------

def main():
    st.set_page_config(
        page_title="LLM Security Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Parse args
    db_path = "security_metrics.db"
    results_dir = Path("/tmp/llm_security_logs")

    # Check for command line args after '--'
    if "--db" in sys.argv:
        idx = sys.argv.index("--db")
        if idx + 1 < len(sys.argv):
            db_path = sys.argv[idx + 1]

    if "--results-dir" in sys.argv:
        idx = sys.argv.index("--results-dir")
        if idx + 1 < len(sys.argv):
            results_dir = Path(sys.argv[idx + 1])

    # Sidebar
    st.sidebar.title("🛡️ LLM Security")
    st.sidebar.caption("Real-Time Telemetry Dashboard")
    st.sidebar.divider()

    page = st.sidebar.radio(
        "Navigation",
        ["Overview", "ASR Trends", "Compliance Posture", "Session Detail", "Live Feed"],
    )

    st.sidebar.divider()
    st.sidebar.caption(f"DB: `{db_path}`")
    st.sidebar.caption(f"Results: `{results_dir}`")
    st.sidebar.caption(f"Updated: {datetime.now().strftime('%H:%M:%S')}")

    if st.sidebar.button("🔄 Refresh Data"):
        st.rerun()

    # Connect to DB
    db_file = Path(db_path)
    if not db_file.exists():
        # Try relative to project root
        project_root = Path(__file__).resolve().parent.parent.parent
        db_file = project_root / db_path
        if not db_file.exists():
            db_file = project_root / "src" / db_path

    conn = get_connection(str(db_file))

    # Route to page
    if page == "Overview":
        page_overview(conn, results_dir)
    elif page == "ASR Trends":
        page_asr_trends(conn)
    elif page == "Compliance Posture":
        page_compliance(conn)
    elif page == "Session Detail":
        page_session_detail(conn)
    elif page == "Live Feed":
        page_live_feed(results_dir)

    conn.close()


if __name__ == "__main__":
    main()
