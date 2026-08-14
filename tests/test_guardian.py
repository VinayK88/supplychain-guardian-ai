from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from supplychain_guardian.cli import scenario_paths
from supplychain_guardian.graph import dependency_adjacency, impacted_nodes
from supplychain_guardian.parsers import load_document
from supplychain_guardian.risk_model import FEATURE_NAMES, LogisticRiskModel
from supplychain_guardian.sarif import report_to_sarif
from supplychain_guardian.scanner import PROJECT_ROOT, scan_bundle


class ScenarioTests(unittest.TestCase):
    def test_secure_fixture_is_allowed(self) -> None:
        report = scan_bundle(*scenario_paths(PROJECT_ROOT, "secure"), scenario="secure")
        self.assertEqual(report.decision, "ALLOW")
        self.assertLess(report.risk_score, 35)
        self.assertEqual(report.findings, [])

    def test_compromised_fixture_is_blocked_with_integrity_evidence(self) -> None:
        report = scan_bundle(*scenario_paths(PROJECT_ROOT, "compromised"), scenario="compromised")
        finding_ids = {finding.finding_id for finding in report.findings}
        self.assertEqual(report.decision, "BLOCK")
        self.assertGreaterEqual(report.risk_score, 95)
        self.assertIn("PROV-001-DIGEST", finding_ids)
        self.assertTrue(any("TYPOSQUAT" in finding_id for finding_id in finding_ids))
        self.assertTrue(any("PIPE-SHELL" in finding_id for finding_id in finding_ids))

    def test_report_is_deterministic_except_timestamp(self) -> None:
        first = scan_bundle(*scenario_paths(PROJECT_ROOT, "compromised"), scenario="compromised").to_dict()
        second = scan_bundle(*scenario_paths(PROJECT_ROOT, "compromised"), scenario="compromised").to_dict()
        first.pop("generated_at")
        second.pop("generated_at")
        self.assertEqual(first, second)


class GraphTests(unittest.TestCase):
    def test_compromised_dependency_reaches_dependents(self) -> None:
        sbom, _ = load_document(PROJECT_ROOT / "data" / "sboms" / "compromised.cdx.json")
        graph = dependency_adjacency(sbom)
        impacted = impacted_nodes(graph, "pkg:pypi/reqeusts@99.0.0")
        self.assertIn("guardian-app", impacted)
        self.assertIn("gateway", impacted)
        self.assertIn("trainer", impacted)


class ModelTests(unittest.TestCase):
    def test_small_logistic_model_learns_direction(self) -> None:
        benign = {name: 0.0 for name in FEATURE_NAMES}
        risky = {name: 2.0 for name in FEATURE_NAMES}
        model = LogisticRiskModel.untrained().fit([benign] * 10 + [risky] * 10, [0] * 10 + [1] * 10, epochs=600)
        self.assertLess(model.predict_proba(benign), 0.2)
        self.assertGreater(model.predict_proba(risky), 0.8)

    def test_model_round_trip(self) -> None:
        model = LogisticRiskModel.untrained()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.json"
            model.save(path)
            restored = LogisticRiskModel.load(path)
        self.assertEqual(list(restored.feature_names), list(model.feature_names))
        self.assertEqual(restored.weights, model.weights)


class ExportTests(unittest.TestCase):
    def test_sarif_contains_one_result_per_finding(self) -> None:
        report = scan_bundle(*scenario_paths(PROJECT_ROOT, "compromised"), scenario="compromised")
        sarif = report_to_sarif(report)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), len(report.findings))
        json.dumps(sarif)


if __name__ == "__main__":
    unittest.main()

