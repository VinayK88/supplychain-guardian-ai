"""Typed domain objects shared by the scanner, API, CLI, and dashboard."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    category: str
    subject: str
    evidence: str
    remediation: str
    confidence: float = 1.0
    blast_radius: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    scenario: str
    risk_score: int
    decision: str
    findings: list[Finding]
    model_version: str
    model_probability: float
    feature_values: dict[str, float]
    model_explanation: list[dict[str, float | str]]
    components_scanned: int
    workflow_steps_scanned: int
    artifact_name: str
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    data_classification: str = "synthetic-demo"

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_RANK}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @property
    def max_blast_radius(self) -> int:
        return max((finding.blast_radius for finding in self.findings), default=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "generated_at": self.generated_at,
            "data_classification": self.data_classification,
            "summary": {
                "risk_score": self.risk_score,
                "decision": self.decision,
                "model_probability": round(self.model_probability, 6),
                "components_scanned": self.components_scanned,
                "workflow_steps_scanned": self.workflow_steps_scanned,
                "artifact_name": self.artifact_name,
                "finding_count": len(self.findings),
                "severity_counts": self.severity_counts,
                "max_blast_radius": self.max_blast_radius,
            },
            "model": {
                "version": self.model_version,
                "features": self.feature_values,
                "explanation": self.model_explanation,
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_RANK.get(finding.severity, 0),
            -finding.blast_radius,
            finding.finding_id,
        ),
    )

