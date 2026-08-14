"""Interactive reviewer dashboard for SupplyChain Guardian AI."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from supplychain_guardian.cli import scenario_paths  # noqa: E402
from supplychain_guardian.sarif import report_to_sarif  # noqa: E402
from supplychain_guardian.scanner import scan_bundle, scan_documents  # noqa: E402


INK = "#172033"
ORANGE = "#f97316"
GOLD = "#f59e0b"
BLUE = "#2563eb"
OPEN = "#fff7ed"
GRID = "#e5e7eb"


st.set_page_config(page_title="SupplyChain Guardian AI", page_icon="🛡️", layout="wide")
st.markdown(
    """
    <style>
    .stApp { background: #fbfcfe; color: #172033; }
    [data-testid="stMetric"] { background: white; border: 1px solid #e5e7eb;
      border-radius: 14px; padding: 16px; box-shadow: 0 8px 24px rgba(23,32,51,.05); }
    .guardian-hero { background: linear-gradient(110deg,#fff7ed,#ffffff 62%);
      border: 1px solid #fed7aa; border-radius: 18px; padding: 22px 26px; margin-bottom: 18px; }
    .guardian-kicker { color: #c2410c; font-weight: 750; letter-spacing: .08em; font-size: .78rem; }
    .guardian-hero h1 { margin: .25rem 0; color: #172033; }
    .guardian-muted { color: #596579; }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_uploaded(uploaded_file, kind: str) -> tuple[dict, str]:
    raw = uploaded_file.getvalue().decode("utf-8")
    document = yaml.safe_load(raw) if kind == "workflow" else json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("The uploaded document must have an object at its root")
    return document, raw


def render_severity_chart(report) -> None:
    order = ["critical", "high", "medium", "low"]
    frame = pd.DataFrame(
        {"Severity": [value.title() for value in order], "Findings": [report.severity_counts[value] for value in order]}
    )
    figure = px.bar(frame, x="Severity", y="Findings", text="Findings")
    figure.update_traces(marker_color=ORANGE, marker_line_color="#9a3412", marker_line_width=1)
    figure.update_layout(
        title="Findings by severity",
        title_subtitle_text="Count of evidence-backed findings in this scan",
        paper_bgcolor="white",
        plot_bgcolor="white",
        font_color=INK,
        showlegend=False,
        yaxis=dict(gridcolor=GRID, rangemode="tozero", dtick=1),
        xaxis=dict(title=""),
        margin=dict(l=30, r=20, t=80, b=35),
    )
    st.plotly_chart(figure, use_container_width=True)


def render_blast_radius(report) -> None:
    rows = sorted(report.findings, key=lambda item: item.blast_radius, reverse=True)[:7]
    frame = pd.DataFrame(
        {"Finding": [item.title for item in rows], "Reachable services": [item.blast_radius for item in rows]}
    ).sort_values("Reachable services")
    figure = px.bar(frame, x="Reachable services", y="Finding", orientation="h", text="Reachable services")
    figure.update_traces(marker_color=GOLD, marker_line_color="#92400e", marker_line_width=1)
    figure.update_layout(
        title="Largest potential blast radii",
        title_subtitle_text="Synthetic reachable-service count; top seven findings",
        paper_bgcolor="white",
        plot_bgcolor="white",
        font_color=INK,
        showlegend=False,
        xaxis=dict(gridcolor=GRID, rangemode="tozero", dtick=1),
        yaxis=dict(title=""),
        margin=dict(l=20, r=20, t=80, b=35),
    )
    st.plotly_chart(figure, use_container_width=True)


def render_model_explanation(report) -> None:
    frame = pd.DataFrame(report.model_explanation).sort_values("contribution")
    colors = [BLUE if value < 0 else ORANGE for value in frame["contribution"]]
    figure = go.Figure(
        go.Bar(
            x=frame["contribution"],
            y=frame["feature"].str.replace("_", " ").str.title(),
            orientation="h",
            marker=dict(color=colors, line=dict(color=INK, width=0.5)),
            text=[f"{value:+.2f}" for value in frame["contribution"]],
            textposition="outside",
        )
    )
    figure.add_vline(x=0, line_color=INK, line_width=1)
    figure.update_layout(
        title="Model contribution by feature",
        title_subtitle_text="Orange raises predicted compromise risk; blue lowers it",
        paper_bgcolor="white",
        plot_bgcolor="white",
        font_color=INK,
        xaxis=dict(title="Log-odds contribution", gridcolor=GRID),
        yaxis=dict(title=""),
        showlegend=False,
        margin=dict(l=20, r=55, t=80, b=40),
    )
    st.plotly_chart(figure, use_container_width=True)


st.markdown(
    """
    <div class="guardian-hero">
      <div class="guardian-kicker">EVIDENCE → ML RANKING → POLICY</div>
      <h1>SupplyChain Guardian AI</h1>
      <div class="guardian-muted">Can we trust this dependency, workflow, and build artifact enough to release it?</div>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("Scan controls")
    mode = st.radio("Input", ["Built-in demo", "Upload documents"])
    scenario = st.selectbox("Scenario", ["compromised", "secure"], disabled=mode != "Built-in demo")
    st.caption("All built-in examples are synthetic and safe.")

try:
    if mode == "Built-in demo":
        report = scan_bundle(*scenario_paths(ROOT, scenario), scenario=scenario)
    else:
        sbom_file = st.sidebar.file_uploader("CycloneDX SBOM", type=["json"])
        workflow_file = st.sidebar.file_uploader("GitHub Actions workflow", type=["yml", "yaml"])
        attestation_file = st.sidebar.file_uploader("Attestation", type=["json"])
        if not all([sbom_file, workflow_file, attestation_file]):
            st.info("Upload all three documents to start the scan.")
            st.stop()
        sbom, _ = load_uploaded(sbom_file, "sbom")
        workflow, workflow_raw = load_uploaded(workflow_file, "workflow")
        attestation, _ = load_uploaded(attestation_file, "attestation")
        report = scan_documents(
            sbom,
            workflow,
            attestation,
            workflow_raw=workflow_raw,
            scenario="uploaded",
        )
except Exception as exc:
    st.error(f"The scan could not be completed: {exc}")
    st.stop()

metric_columns = st.columns(5)
metric_columns[0].metric("Release decision", report.decision)
metric_columns[1].metric("Risk score", f"{report.risk_score}/100")
metric_columns[2].metric("Findings", len(report.findings))
metric_columns[3].metric("Components", report.components_scanned)
metric_columns[4].metric("Max blast radius", report.max_blast_radius)

if report.decision == "BLOCK":
    st.error("Release blocked: resolve critical evidence or replace the artifact before promotion.")
elif report.decision == "REVIEW":
    st.warning("Manual review required: verify the highlighted evidence before promotion.")
else:
    st.success("No blocking evidence found in this bounded scan. Continue normal release controls.")

left, right = st.columns(2)
with left:
    render_severity_chart(report)
with right:
    render_blast_radius(report)

st.subheader("Why the model scored it this way")
render_model_explanation(report)

st.subheader("Evidence and remediation")
finding_rows = [
    {
        "Severity": finding.severity.upper(),
        "Category": finding.category,
        "Finding": finding.title,
        "Subject": finding.subject,
        "Blast radius": finding.blast_radius,
        "Evidence": finding.evidence,
        "Recommended action": finding.remediation,
    }
    for finding in report.findings
]
if finding_rows:
    st.dataframe(pd.DataFrame(finding_rows), use_container_width=True, hide_index=True)
else:
    st.info("No findings were produced by the bounded demo rules.")

json_payload = json.dumps(report.to_dict(), indent=2)
sarif_payload = json.dumps(report_to_sarif(report), indent=2)
download_left, download_right = st.columns(2)
download_left.download_button("Download JSON report", json_payload, "guardian-report.json", "application/json")
download_right.download_button("Download SARIF", sarif_payload, "guardian-report.sarif", "application/json")

st.caption(
    "Demo verifier: validates declared digest, builder, signature-presence, and transparency-log fields. "
    "Production deployments should call a real Sigstore/GitHub attestation verifier."
)

