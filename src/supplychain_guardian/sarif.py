"""Export Guardian findings as SARIF 2.1.0 for CI and code-scanning tools."""

from __future__ import annotations

from typing import Any

from .models import ScanReport


SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def report_to_sarif(report: ScanReport) -> dict[str, Any]:
    rules = []
    results = []
    for finding in report.findings:
        rules.append(
            {
                "id": finding.finding_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation},
                "properties": {"category": finding.category, "severity": finding.severity},
            }
        )
        results.append(
            {
                "ruleId": finding.finding_id,
                "level": SARIF_LEVEL.get(finding.severity, "note"),
                "message": {"text": f"{finding.subject}: {finding.evidence}"},
                "properties": {
                    "confidence": finding.confidence,
                    "blastRadius": finding.blast_radius,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SupplyChain Guardian AI",
                        "informationUri": "https://github.com/VinayK88/supplychain-guardian-ai",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

