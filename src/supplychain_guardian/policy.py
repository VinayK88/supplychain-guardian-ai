"""Human-readable policy gate layered on the learned risk score."""

from __future__ import annotations

from .models import Finding


def release_decision(risk_score: int, findings: list[Finding]) -> str:
    if risk_score >= 75 or any(finding.severity == "critical" for finding in findings):
        return "BLOCK"
    if risk_score >= 35 or any(finding.severity == "high" for finding in findings):
        return "REVIEW"
    return "ALLOW"


def apply_guardrails(model_score: int, findings: list[Finding]) -> int:
    score = model_score
    if any(finding.finding_id == "PROV-001-DIGEST" for finding in findings):
        score = max(score, 95)
    elif any(finding.severity == "critical" for finding in findings):
        score = max(score, 85)
    elif sum(finding.severity == "high" for finding in findings) >= 3:
        score = max(score, 72)
    return min(score, 100)

