"""Rebuild the synthetic corpus, learned model, reports, SARIF, and README visuals."""

from __future__ import annotations

import csv
import json
import math
import random
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from supplychain_guardian.cli import scenario_paths  # noqa: E402
from supplychain_guardian.risk_model import FEATURE_NAMES, LogisticRiskModel  # noqa: E402
from supplychain_guardian.sarif import report_to_sarif  # noqa: E402
from supplychain_guardian.scanner import scan_bundle  # noqa: E402


ORANGE = "#f97316"
GOLD = "#f59e0b"
BLUE = "#2563eb"
INK = "#172033"
MUTED = "#667085"
GRID = "#e5e7eb"
OPEN = "#fff7ed"


def sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-value))


def make_training_corpus(seed: int = 42, size: int = 480) -> list[dict[str, float | int | str]]:
    randomizer = random.Random(seed)
    rows: list[dict[str, float | int | str]] = []
    families = ["trusted_release", "dependency_takeover", "workflow_compromise", "tampered_provenance", "noisy_review"]
    for index in range(size):
        family = families[index % len(families)]
        if family == "trusted_release":
            features = [0, 0, randomizer.randint(0, 1), randomizer.randint(0, 2), 0, 0, 0, randomizer.uniform(0, 0.2)]
        elif family == "dependency_takeover":
            features = [randomizer.randint(0, 1), randomizer.randint(1, 3), randomizer.randint(0, 3), randomizer.randint(0, 2), 0, randomizer.randint(0, 1), randomizer.randint(1, 4), randomizer.uniform(0.25, 1.0)]
        elif family == "workflow_compromise":
            features = [randomizer.randint(0, 1), randomizer.randint(2, 5), randomizer.randint(1, 4), randomizer.randint(0, 2), 0, randomizer.randint(3, 7), randomizer.randint(0, 1), randomizer.uniform(0.2, 0.8)]
        elif family == "tampered_provenance":
            features = [1, randomizer.randint(2, 4), randomizer.randint(0, 2), 0, randomizer.randint(3, 4), randomizer.randint(0, 2), randomizer.randint(0, 1), randomizer.uniform(0.5, 1.0)]
        else:
            features = [0, randomizer.randint(0, 2), randomizer.randint(1, 5), randomizer.randint(0, 4), randomizer.randint(0, 1), randomizer.randint(0, 3), randomizer.randint(0, 2), randomizer.uniform(0.1, 0.65)]
        feature_map = dict(zip(FEATURE_NAMES, (float(value) for value in features), strict=True))
        logit = (
            -5.0
            + 2.15 * feature_map["critical_count"]
            + 0.82 * feature_map["high_count"]
            + 0.24 * feature_map["medium_count"]
            + 0.06 * feature_map["low_count"]
            + 1.15 * feature_map["provenance_failures"]
            + 0.48 * feature_map["workflow_exposures"]
            + 0.62 * feature_map["vulnerable_components"]
            + 1.05 * feature_map["blast_ratio"]
            + randomizer.gauss(0, 0.65)
        )
        label = int(randomizer.random() < sigmoid(logit))
        rows.append(
            {
                "scan_id": f"SYN-{index + 1:04d}",
                "family": family,
                "split": "test" if index % 4 == 0 else "train",
                **{name: round(feature_map[name], 5) for name in FEATURE_NAMES},
                "compromised": label,
            }
        )
    return rows


def classification_metrics(labels: list[int], probabilities: list[float]) -> dict[str, float | int]:
    predictions = [int(probability >= 0.5) for probability in probabilities]
    true_positive = sum(label == 1 and prediction == 1 for label, prediction in zip(labels, predictions, strict=True))
    true_negative = sum(label == 0 and prediction == 0 for label, prediction in zip(labels, predictions, strict=True))
    false_positive = sum(label == 0 and prediction == 1 for label, prediction in zip(labels, predictions, strict=True))
    false_negative = sum(label == 1 and prediction == 0 for label, prediction in zip(labels, predictions, strict=True))
    precision = true_positive / max(true_positive + false_positive, 1)
    recall = true_positive / max(true_positive + false_negative, 1)
    return {
        "rows": len(labels),
        "accuracy": (true_positive + true_negative) / max(len(labels), 1),
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / max(precision + recall, 1.0e-12),
        "brier": sum((probability - label) ** 2 for label, probability in zip(labels, probabilities, strict=True)) / max(len(labels), 1),
        "confusion_matrix": [[true_negative, false_positive], [false_negative, true_positive]],
    }


def train_and_save(rows: list[dict[str, float | int | str]]) -> dict[str, object]:
    train_rows = [row for row in rows if row["split"] == "train"]
    test_rows = [row for row in rows if row["split"] == "test"]
    model = LogisticRiskModel.untrained().fit(
        [{name: float(row[name]) for name in FEATURE_NAMES} for row in train_rows],
        [int(row["compromised"]) for row in train_rows],
    )
    model.save(ROOT / "models" / "risk_model.json")
    labels = [int(row["compromised"]) for row in test_rows]
    probabilities = [model.predict_proba({name: float(row[name]) for name in FEATURE_NAMES}) for row in test_rows]
    metrics = classification_metrics(labels, probabilities)
    return {
        "model": model.to_dict(),
        "training": {
            "source": "deterministic synthetic scenario generator",
            "seed": 42,
            "train_rows": len(train_rows),
            "test_rows": len(test_rows),
            "families": sorted({str(row["family"]) for row in rows}),
        },
        "held_out_metrics": metrics,
        "limitations": [
            "Synthetic labels validate the pipeline, not production generalization.",
            "Package reputation and vulnerability properties are fixture fields, not live threat intelligence.",
            "The policy gate remains authoritative for critical evidence.",
        ],
    }


def write_csv(rows: list[dict[str, float | int | str]]) -> None:
    path = ROOT / "data" / "synthetic_scans.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def text(x: int, y: int, value: str, *, size: int = 18, weight: int = 500, fill: str = INK, anchor: str = "start") -> str:
    escaped = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f'<text x="{x}" y="{y}" font-family="Inter,Arial,sans-serif" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{escaped}</text>'


def architecture_svg() -> str:
    nodes = [
        (45, "SBOM + workflow + artifact"),
        (315, "Evidence rules"),
        (555, "Explainable ML ranker"),
        (825, "Policy gate"),
        (1045, "ALLOW / REVIEW / BLOCK"),
    ]
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="1320" height="300" viewBox="0 0 1320 300">', '<rect width="1320" height="300" fill="#ffffff"/>']
    parts.append('<path d="M0 14 H1320" stroke="#f97316" stroke-width="8"/>')
    parts.append(text(46, 55, "SUPPLYCHAIN GUARDIAN AI", size=14, weight=800, fill="#c2410c"))
    parts.append(text(46, 88, "Trust decisions that preserve the evidence trail", size=25, weight=750))
    widths = [220, 190, 220, 165, 230]
    for index, ((x, label), width) in enumerate(zip(nodes, widths, strict=True)):
        fill = OPEN if index in {0, 2, 4} else "#f8fafc"
        parts.append(f'<rect x="{x}" y="130" width="{width}" height="88" rx="16" fill="{fill}" stroke="#fed7aa"/>')
        parts.append(text(x + width // 2, 168, label.split(" + ")[0], size=15, weight=700, anchor="middle"))
        if " + " in label:
            parts.append(text(x + width // 2, 193, "+ " + label.split(" + ", 1)[1], size=13, fill=MUTED, anchor="middle"))
        if index < len(nodes) - 1:
            next_x = nodes[index + 1][0]
            parts.append(f'<path d="M{x + width + 8} 174 H{next_x - 16}" stroke="#f97316" stroke-width="3" marker-end="url(#arrow)"/>')
    parts.append('<defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#f97316"/></marker></defs>')
    parts.append(text(46, 270, "Deterministic evidence stays visible; ML prioritizes; policy keeps critical integrity checks non-negotiable.", size=15, fill=MUTED))
    parts.append("</svg>")
    return "".join(parts)


def dashboard_svg(report) -> str:
    counts = report.severity_counts
    cards = [
        ("RELEASE", report.decision),
        ("RISK SCORE", f"{report.risk_score}/100"),
        ("FINDINGS", str(len(report.findings))),
        ("COMPONENTS", str(report.components_scanned)),
        ("BLAST RADIUS", str(report.max_blast_radius)),
    ]
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="1320" height="700" viewBox="0 0 1320 700">', '<rect width="1320" height="700" fill="#f8fafc"/>']
    parts.append('<rect x="30" y="26" width="1260" height="105" rx="20" fill="#fff7ed" stroke="#fed7aa"/>')
    parts.append(text(58, 58, "EVIDENCE → ML RANKING → POLICY", size=13, weight=800, fill="#c2410c"))
    parts.append(text(58, 91, "SupplyChain Guardian AI", size=28, weight=800))
    parts.append(text(58, 116, "Synthetic compromised-release walkthrough", size=14, fill=MUTED))
    for index, (label, value) in enumerate(cards):
        x = 30 + index * 252
        parts.append(f'<rect x="{x}" y="150" width="232" height="105" rx="14" fill="#ffffff" stroke="{GRID}"/>')
        parts.append(text(x + 18, 180, label, size=12, weight=750, fill=MUTED))
        parts.append(text(x + 18, 225, value, size=27, weight=800, fill=ORANGE if index < 2 else INK))
    parts.append('<rect x="30" y="277" width="610" height="365" rx="16" fill="#ffffff" stroke="#e5e7eb"/>')
    parts.append(text(55, 315, "Findings by severity", size=19, weight=750))
    parts.append(text(55, 338, "Evidence-backed finding count", size=13, fill=MUTED))
    severities = ["Critical", "High", "Medium", "Low"]
    values = [counts[severity.lower()] for severity in severities]
    maximum = max(values + [1])
    for index, (label, value) in enumerate(zip(severities, values, strict=True)):
        y = 382 + index * 58
        width = int(390 * value / maximum)
        parts.append(text(55, y + 19, label, size=14))
        parts.append(f'<rect x="155" y="{y}" width="390" height="24" rx="5" fill="#f3f4f6"/>')
        parts.append(f'<rect x="155" y="{y}" width="{width}" height="24" rx="5" fill="{ORANGE}" stroke="#9a3412"/>')
        parts.append(text(565, y + 19, str(value), size=14, weight=750, anchor="end"))
    parts.append('<rect x="662" y="277" width="628" height="365" rx="16" fill="#ffffff" stroke="#e5e7eb"/>')
    parts.append(text(687, 315, "Top evidence", size=19, weight=750))
    parts.append(text(687, 338, "The release is blocked by integrity evidence, not by a black-box label", size=13, fill=MUTED))
    for index, finding in enumerate(report.findings[:5]):
        y = 380 + index * 48
        parts.append(f'<circle cx="701" cy="{y - 5}" r="6" fill="{ORANGE if finding.severity in {"critical", "high"} else GOLD}"/>')
        parts.append(text(720, y, finding.title[:58], size=14, weight=650))
        parts.append(text(1248, y, finding.severity.upper(), size=11, weight=800, fill="#c2410c", anchor="end"))
    parts.append(text(45, 680, "All values shown are from versioned, synthetic fixtures. No live packages or production systems are scanned.", size=13, fill=MUTED))
    parts.append("</svg>")
    return "".join(parts)


def main() -> None:
    rows = make_training_corpus()
    write_csv(rows)
    model_report = train_and_save(rows)
    (ROOT / "reports" / "model-evaluation.json").write_text(json.dumps(model_report, indent=2) + "\n", encoding="utf-8")

    reports = {}
    for scenario in ("secure", "compromised"):
        report = scan_bundle(*scenario_paths(ROOT, scenario), scenario=scenario)
        report.generated_at = "2026-08-14T00:00:00+00:00"
        reports[scenario] = report
        (ROOT / "reports" / f"{scenario}-scan.json").write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
        (ROOT / "reports" / f"{scenario}-scan.sarif").write_text(json.dumps(report_to_sarif(report), indent=2) + "\n", encoding="utf-8")

    (ROOT / "assets" / "architecture.svg").write_text(architecture_svg(), encoding="utf-8")
    (ROOT / "assets" / "dashboard-preview.svg").write_text(dashboard_svg(reports["compromised"]), encoding="utf-8")
    print(json.dumps({"model": model_report["held_out_metrics"], "reports": {name: report.to_dict()["summary"] for name, report in reports.items()}}, indent=2))


if __name__ == "__main__":
    main()
