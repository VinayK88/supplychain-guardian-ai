"""Orchestrates evidence collection, ML scoring, explanations, and policy decisions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import ScanReport, sort_findings
from .parsers import load_document
from .policy import apply_guardrails, release_decision
from .risk_model import LogisticRiskModel, finding_features
from .rules import scan_attestation, scan_sbom, scan_workflow


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "risk_model.json"


def _fallback_model() -> LogisticRiskModel:
    return LogisticRiskModel(
        feature_names=(
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "provenance_failures",
            "workflow_exposures",
            "vulnerable_components",
            "blast_ratio",
        ),
        weights=[1.8, 1.0, 0.45, 0.1, 1.3, 0.75, 0.9, 1.1],
        intercept=-4.5,
        means=[0.0] * 8,
        scales=[1.0] * 8,
        version="guardian-fallback-v1",
    )


def load_model(path: str | Path | None = None) -> LogisticRiskModel:
    source = Path(path) if path else DEFAULT_MODEL_PATH
    return LogisticRiskModel.load(source) if source.exists() else _fallback_model()


def scan_documents(
    sbom: dict[str, Any],
    workflow: dict[str, Any],
    attestation: dict[str, Any],
    *,
    workflow_raw: str = "",
    scenario: str = "custom",
    model_path: str | Path | None = None,
) -> ScanReport:
    sbom_findings, component_count = scan_sbom(sbom)
    workflow_findings, step_count = scan_workflow(workflow, workflow_raw)
    provenance_findings, artifact_name = scan_attestation(attestation)
    findings = sort_findings(sbom_findings + workflow_findings + provenance_findings)
    features = finding_features(findings, component_count)
    model = load_model(model_path)
    probability = model.predict_proba(features)
    guarded_score = apply_guardrails(round(probability * 100), findings)
    return ScanReport(
        scenario=scenario,
        risk_score=guarded_score,
        decision=release_decision(guarded_score, findings),
        findings=findings,
        model_version=model.version,
        model_probability=probability,
        feature_values={key: round(value, 4) for key, value in features.items()},
        model_explanation=model.explain(features),
        components_scanned=component_count,
        workflow_steps_scanned=step_count,
        artifact_name=artifact_name,
    )


def scan_bundle(
    sbom_path: str | Path,
    workflow_path: str | Path,
    attestation_path: str | Path,
    *,
    scenario: str = "custom",
    model_path: str | Path | None = None,
) -> ScanReport:
    sbom, _ = load_document(sbom_path)
    workflow, workflow_raw = load_document(workflow_path)
    attestation, _ = load_document(attestation_path)
    return scan_documents(
        sbom,
        workflow,
        attestation,
        workflow_raw=workflow_raw,
        scenario=scenario,
        model_path=model_path,
    )

