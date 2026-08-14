"""Small, auditable logistic risk model implemented with the Python standard library."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .models import Finding


FEATURE_NAMES = (
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "provenance_failures",
    "workflow_exposures",
    "vulnerable_components",
    "blast_ratio",
)


def finding_features(findings: Iterable[Finding], components_scanned: int) -> dict[str, float]:
    items = list(findings)
    return {
        "critical_count": float(sum(item.severity == "critical" for item in items)),
        "high_count": float(sum(item.severity == "high" for item in items)),
        "medium_count": float(sum(item.severity == "medium" for item in items)),
        "low_count": float(sum(item.severity == "low" for item in items)),
        "provenance_failures": float(sum(item.category == "provenance" for item in items)),
        "workflow_exposures": float(sum(item.category == "ci-cd" for item in items)),
        "vulnerable_components": float(
            len({item.subject for item in items if item.category in {"vulnerability", "dependency"}})
        ),
        "blast_ratio": float(
            max((item.blast_radius for item in items), default=0) / max(components_scanned, 1)
        ),
    }


@dataclass
class LogisticRiskModel:
    feature_names: Sequence[str]
    weights: list[float]
    intercept: float
    means: list[float]
    scales: list[float]
    version: str = "guardian-logistic-v1"

    @classmethod
    def untrained(cls) -> "LogisticRiskModel":
        size = len(FEATURE_NAMES)
        return cls(FEATURE_NAMES, [0.0] * size, 0.0, [0.0] * size, [1.0] * size)

    @staticmethod
    def _sigmoid(value: float) -> float:
        if value >= 0:
            return 1.0 / (1.0 + math.exp(-value))
        exp_value = math.exp(value)
        return exp_value / (1.0 + exp_value)

    def _vector(self, features: dict[str, float]) -> list[float]:
        return [float(features.get(name, 0.0)) for name in self.feature_names]

    def _standardize(self, vector: Sequence[float]) -> list[float]:
        return [
            (value - mean) / (scale if scale > 1e-12 else 1.0)
            for value, mean, scale in zip(vector, self.means, self.scales, strict=True)
        ]

    def fit(
        self,
        rows: Sequence[dict[str, float]],
        labels: Sequence[int],
        *,
        learning_rate: float = 0.08,
        epochs: int = 1800,
        l2: float = 0.02,
    ) -> "LogisticRiskModel":
        if not rows or len(rows) != len(labels):
            raise ValueError("Training rows and labels must be non-empty and have equal length")
        vectors = [[float(row.get(name, 0.0)) for name in self.feature_names] for row in rows]
        width = len(self.feature_names)
        self.means = [sum(row[index] for row in vectors) / len(vectors) for index in range(width)]
        self.scales = []
        for index, mean in enumerate(self.means):
            variance = sum((row[index] - mean) ** 2 for row in vectors) / len(vectors)
            self.scales.append(max(math.sqrt(variance), 1.0e-6))
        standardized = [self._standardize(row) for row in vectors]
        self.weights = [0.0] * width
        positive_rate = min(max(sum(labels) / len(labels), 1.0e-4), 1 - 1.0e-4)
        self.intercept = math.log(positive_rate / (1 - positive_rate))

        for _ in range(epochs):
            gradient = [0.0] * width
            intercept_gradient = 0.0
            for row, label in zip(standardized, labels, strict=True):
                probability = self._sigmoid(
                    self.intercept + sum(weight * value for weight, value in zip(self.weights, row))
                )
                error = probability - label
                intercept_gradient += error
                for index, value in enumerate(row):
                    gradient[index] += error * value
            size = float(len(rows))
            self.intercept -= learning_rate * intercept_gradient / size
            for index in range(width):
                regularized = gradient[index] / size + l2 * self.weights[index]
                self.weights[index] -= learning_rate * regularized
        return self

    def predict_proba(self, features: dict[str, float]) -> float:
        vector = self._standardize(self._vector(features))
        logit = self.intercept + sum(
            weight * value for weight, value in zip(self.weights, vector, strict=True)
        )
        return self._sigmoid(logit)

    def explain(self, features: dict[str, float]) -> list[dict[str, float | str]]:
        standardized = self._standardize(self._vector(features))
        explanation = [
            {
                "feature": name,
                "value": round(float(features.get(name, 0.0)), 4),
                "contribution": round(weight * value, 4),
            }
            for name, weight, value in zip(
                self.feature_names, self.weights, standardized, strict=True
            )
        ]
        return sorted(explanation, key=lambda item: abs(float(item["contribution"])), reverse=True)

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "feature_names": list(self.feature_names),
            "weights": self.weights,
            "intercept": self.intercept,
            "means": self.means,
            "scales": self.scales,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "LogisticRiskModel":
        return cls(
            feature_names=tuple(str(value) for value in payload["feature_names"]),
            weights=[float(value) for value in payload["weights"]],
            intercept=float(payload["intercept"]),
            means=[float(value) for value in payload["means"]],
            scales=[float(value) for value in payload["scales"]],
            version=str(payload.get("version", "guardian-logistic-v1")),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "LogisticRiskModel":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

