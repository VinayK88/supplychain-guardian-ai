"""Create the three reader-facing notebooks with conclusions derived from the same inputs."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import nbformat as nbf
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from supplychain_guardian.cli import scenario_paths  # noqa: E402
from supplychain_guardian.scanner import scan_bundle  # noqa: E402


ORANGE = "#f97316"
GOLD = "#f59e0b"
BLUE = "#2563eb"
INK = "#172033"
GRID = "#e5e7eb"
FEATURES = [
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "provenance_failures",
    "workflow_exposures",
    "vulnerable_components",
    "blast_ratio",
]


def markdown(value: str):
    return nbf.v4.new_markdown_cell(value.strip())


def code(value: str):
    return nbf.v4.new_code_cell(value.strip())


def notebook(cells: list) -> nbf.NotebookNode:
    document = nbf.v4.new_notebook(cells=cells)
    document.metadata.kernelspec = {"display_name": "Python 3", "language": "python", "name": "python3"}
    document.metadata.language_info = {"name": "python", "version": "3.11"}
    return document


def common_setup() -> str:
    return f"""
from pathlib import Path
import json
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path.cwd().resolve()
while ROOT != ROOT.parent and not (ROOT / "pyproject.toml").exists():
    ROOT = ROOT.parent
if not (ROOT / "pyproject.toml").exists():
    raise RuntimeError("Run this notebook from the repository or a child directory")
sys.path.insert(0, str(ROOT / "src"))

ORANGE = "{ORANGE}"
GOLD = "{GOLD}"
BLUE = "{BLUE}"
INK = "{INK}"
GRID = "{GRID}"
plt.rcParams.update({{
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": INK,
    "axes.labelcolor": INK,
    "axes.titlecolor": INK,
    "text.color": INK,
    "xtick.color": INK,
    "ytick.color": INK,
    "font.size": 11,
}})
"""


def build_sbom_notebook() -> nbf.NotebookNode:
    report = scan_bundle(*scenario_paths(ROOT, "compromised"), scenario="compromised")
    counts = report.severity_counts
    top = max(report.findings, key=lambda finding: finding.blast_radius)
    return notebook(
        [
            markdown("""
            # 01 · SBOM Risk & Dependency Blast Radius

            A reproducible investigation of a **synthetic dependency takeover** using CycloneDX data, evidence rules, and graph reachability.
            """),
            markdown(f"""
            ## tl;dr

            The compromised fixture is **{report.decision}** at **{report.risk_score}/100**. The scanner found **{len(report.findings)} findings** across **{report.components_scanned} components**, including **{counts['critical']} critical** and **{counts['high']} high-severity findings**. The widest single finding can affect **{top.blast_radius} synthetic services**.
            """),
            markdown("""
            ## Context & Methods

            We parse one versioned CycloneDX fixture, run the repository's deterministic evidence rules, and separately examine dependency reachability. Rules establish *what happened*; the learned model only ranks the combined release risk.

            ### Key Assumptions

            - Package reputation, advisory, and reachability fields beginning with `guardian:` are synthetic labels.
            - A graph edge means “depends on,” not proof that a vulnerable function is called.
            - Blast radius is a prioritization aid, not an exploitability claim.
            """),
            markdown("## Data\n\nLoad the versioned SBOM and checked-in scan output so every number is traceable."),
            code(common_setup()),
            code("""
from supplychain_guardian.graph import dependency_adjacency, impacted_nodes
from supplychain_guardian.parsers import load_document
from supplychain_guardian.scanner import scan_bundle

sbom_path = ROOT / "data" / "sboms" / "compromised.cdx.json"
workflow_path = ROOT / "data" / "workflows" / "compromised.yml"
attestation_path = ROOT / "data" / "attestations" / "tampered.json"
sbom, _ = load_document(sbom_path)
report = scan_bundle(sbom_path, workflow_path, attestation_path, scenario="compromised")

summary = pd.DataFrame([report.to_dict()["summary"]]).T.rename(columns={0: "value"})
summary
            """),
            code("""
assert sbom["bomFormat"] == "CycloneDX"
assert len(sbom["components"]) == report.components_scanned
assert report.data_classification == "synthetic-demo"
print(f"Validated {report.components_scanned} components and {len(sbom['dependencies'])} dependency records.")
            """),
            markdown("## Results\n\nFirst compare severity counts, then inspect which evidence has the largest reachable footprint."),
            code("""
severity_order = ["critical", "high", "medium", "low"]
values = [report.severity_counts[name] for name in severity_order]
fig, ax = plt.subplots(figsize=(8.6, 4.6))
bars = ax.bar([name.title() for name in severity_order], values, color=ORANGE, edgecolor="#9a3412")
ax.bar_label(bars, padding=4, fontweight="bold")
ax.set_title("Findings by severity", loc="left", fontweight="bold")
ax.set_ylabel("Evidence-backed finding count")
ax.set_ylim(0, max(values) + 1.5)
ax.grid(axis="y", color=GRID, linewidth=0.8)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
            """),
            code("""
finding_frame = pd.DataFrame([
    {
        "finding": item.title,
        "severity": item.severity,
        "category": item.category,
        "blast_radius": item.blast_radius,
        "subject": item.subject,
    }
    for item in report.findings
]).sort_values(["blast_radius", "severity"], ascending=[True, True])

top_findings = finding_frame.tail(8)
fig, ax = plt.subplots(figsize=(10, 5.5))
bars = ax.barh(top_findings["finding"], top_findings["blast_radius"], color=GOLD, edgecolor="#92400e")
ax.bar_label(bars, padding=4, fontweight="bold")
ax.set_title("Largest potential blast radii", loc="left", fontweight="bold")
ax.set_xlabel("Synthetic reachable-service count")
ax.grid(axis="x", color=GRID, linewidth=0.8)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
            """),
            code("""
import networkx as nx

graph_map = dependency_adjacency(sbom)
graph = nx.DiGraph()
for parent, children in graph_map.items():
    for child in children:
        graph.add_edge(parent, child)

compromised_nodes = {"pkg:pypi/reqeusts@99.0.0", "pkg:pypi/build-helper@latest"}
positions = nx.spring_layout(graph, seed=11, k=0.9)
colors = [ORANGE if node in compromised_nodes else BLUE if node == "guardian-app" else "#ffedd5" for node in graph.nodes]
labels = {node: node.replace("pkg:pypi/", "").replace("pkg:generic/", "") for node in graph.nodes}

fig, ax = plt.subplots(figsize=(12, 7))
nx.draw_networkx_edges(graph, positions, ax=ax, edge_color="#94a3b8", arrows=True, arrowsize=16)
nx.draw_networkx_nodes(graph, positions, ax=ax, node_color=colors, edgecolors=INK, node_size=2300)
nx.draw_networkx_labels(graph, positions, labels=labels, ax=ax, font_size=8, font_weight="bold")
ax.set_title("Dependency graph: orange nodes are synthetic compromise fixtures", loc="left", fontweight="bold")
ax.axis("off")
plt.tight_layout()
plt.show()

for node in sorted(compromised_nodes):
    print(node, "can affect", impacted_nodes(graph_map, node))
            """),
            markdown(f"""
            ## Takeaways

            1. **Integrity dominates the decision.** The mismatched artifact digest and unsafe execution path make this a block even before finer ranking.
            2. **Reachability changes priority.** `{top.subject}` has the largest synthetic reach at **{top.blast_radius} services**.
            3. **The graph does not prove exploitation.** Production use should combine SBOM identity, vulnerability status, runtime reachability, and verified provenance.
            """),
        ]
    )


def compute_ml_metrics(frame: pd.DataFrame) -> tuple[dict[str, float], dict[str, float]]:
    train = frame[frame["split"] == "train"]
    test = frame[frame["split"] == "test"]
    classifier = RandomForestClassifier(n_estimators=260, max_depth=6, min_samples_leaf=3, class_weight="balanced", random_state=42)
    classifier.fit(train[FEATURES], train["compromised"])
    probabilities = classifier.predict_proba(test[FEATURES])[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    supervised = {
        "accuracy": accuracy_score(test["compromised"], predictions),
        "precision": precision_score(test["compromised"], predictions, zero_division=0),
        "recall": recall_score(test["compromised"], predictions, zero_division=0),
        "f1": f1_score(test["compromised"], predictions, zero_division=0),
        "roc_auc": roc_auc_score(test["compromised"], probabilities),
    }
    detector = IsolationForest(n_estimators=220, contamination=0.12, random_state=42)
    detector.fit(train.loc[train["compromised"] == 0, FEATURES])
    anomaly_predictions = (detector.predict(test[FEATURES]) == -1).astype(int)
    unsupervised = {
        "precision": precision_score(test["compromised"], anomaly_predictions, zero_division=0),
        "recall": recall_score(test["compromised"], anomaly_predictions, zero_division=0),
        "f1": f1_score(test["compromised"], anomaly_predictions, zero_division=0),
    }
    return supervised, unsupervised


def build_ml_notebook(frame: pd.DataFrame) -> nbf.NotebookNode:
    supervised, unsupervised = compute_ml_metrics(frame)
    return notebook(
        [
            markdown("""
            # 02 · CI/CD Compromise Detection with ML

            A held-out comparison of supervised risk classification and benign-only anomaly detection across five synthetic supply-chain scenario families.
            """),
            markdown(f"""
            ## tl;dr

            On **{sum(frame['split'] == 'test')} held-out synthetic scans**, the random forest reaches **{supervised['f1']:.1%} F1** and **{supervised['roc_auc']:.1%} ROC AUC**. A benign-only Isolation Forest reaches **{unsupervised['f1']:.1%} F1**. The gap demonstrates why labeled compromise examples help—but these synthetic scores are pipeline validation, not a production benchmark.
            """),
            markdown("""
            ## Context & Methods

            We compare two defensible baselines:

            - **Random Forest:** supervised classification using versioned train/test assignments.
            - **Isolation Forest:** anomaly detection fitted only on benign training rows.

            ### Key Assumptions

            - Each row represents one release scan, not an individual package.
            - Features are evidence counts and a bounded blast-radius ratio.
            - The corpus is generated with seed 42; it contains no live incident or customer data.
            """),
            markdown("## Data\n\nLoad the checked-in corpus and validate class, family, and split coverage."),
            code(common_setup()),
            code(f"FEATURES = {FEATURES!r}\nframe = pd.read_csv(ROOT / 'data' / 'synthetic_scans.csv')\nframe.head()"),
            code("""
coverage = frame.groupby(["split", "family", "compromised"]).size().rename("rows").reset_index()
assert set(frame["split"]) == {"train", "test"}
assert frame[FEATURES].notna().all().all()
print(f"Rows: {len(frame)} | Train: {(frame['split'] == 'train').sum()} | Test: {(frame['split'] == 'test').sum()}")
coverage.head(12)
            """),
            markdown("## Results\n\nFit both baselines without allowing test rows to influence training."),
            code("""
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay, PrecisionRecallDisplay, accuracy_score, f1_score,
    precision_score, recall_score, roc_auc_score,
)

train = frame[frame["split"] == "train"].copy()
test = frame[frame["split"] == "test"].copy()

classifier = RandomForestClassifier(
    n_estimators=260, max_depth=6, min_samples_leaf=3,
    class_weight="balanced", random_state=42,
)
classifier.fit(train[FEATURES], train["compromised"])
rf_probability = classifier.predict_proba(test[FEATURES])[:, 1]
rf_prediction = (rf_probability >= 0.5).astype(int)

detector = IsolationForest(n_estimators=220, contamination=0.12, random_state=42)
detector.fit(train.loc[train["compromised"] == 0, FEATURES])
iso_prediction = (detector.predict(test[FEATURES]) == -1).astype(int)

metrics = pd.DataFrame([
    {
        "model": "Random Forest",
        "precision": precision_score(test["compromised"], rf_prediction, zero_division=0),
        "recall": recall_score(test["compromised"], rf_prediction, zero_division=0),
        "f1": f1_score(test["compromised"], rf_prediction, zero_division=0),
        "roc_auc": roc_auc_score(test["compromised"], rf_probability),
    },
    {
        "model": "Isolation Forest",
        "precision": precision_score(test["compromised"], iso_prediction, zero_division=0),
        "recall": recall_score(test["compromised"], iso_prediction, zero_division=0),
        "f1": f1_score(test["compromised"], iso_prediction, zero_division=0),
        "roc_auc": np.nan,
    },
]).set_index("model")
metrics.style.format("{:.1%}")
            """),
            code("""
fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.5))
ConfusionMatrixDisplay.from_predictions(test["compromised"], rf_prediction, ax=axes[0], colorbar=False, cmap="Oranges")
ConfusionMatrixDisplay.from_predictions(test["compromised"], iso_prediction, ax=axes[1], colorbar=False, cmap="Blues")
axes[0].set_title("Random Forest confusion matrix", fontweight="bold")
axes[1].set_title("Isolation Forest confusion matrix", fontweight="bold")
plt.tight_layout()
plt.show()
            """),
            code("""
importance = pd.Series(classifier.feature_importances_, index=FEATURES).sort_values()
fig, ax = plt.subplots(figsize=(9, 5))
bars = ax.barh(importance.index.str.replace("_", " ").str.title(), importance, color=ORANGE, edgecolor="#9a3412")
ax.bar_label(bars, labels=[f"{value:.2f}" for value in importance], padding=4)
ax.set_title("Random Forest feature importance", loc="left", fontweight="bold")
ax.set_xlabel("Mean decrease in impurity (sums to 1)")
ax.grid(axis="x", color=GRID)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
            """),
            code("""
fig, ax = plt.subplots(figsize=(8.5, 5))
PrecisionRecallDisplay.from_predictions(test["compromised"], rf_probability, ax=ax, color=ORANGE)
ax.set_title("Precision–recall across decision thresholds", loc="left", fontweight="bold")
ax.grid(color=GRID)
plt.tight_layout()
plt.show()
            """),
            markdown(f"""
            ## Takeaways

            1. The supervised model achieves **{supervised['precision']:.1%} precision** and **{supervised['recall']:.1%} recall** on the fixed held-out split.
            2. The benign-only detector reaches **{unsupervised['recall']:.1%} recall** but has a different error profile, making it useful as a secondary signal rather than the sole release gate.
            3. Production evaluation needs time-based splits, real false-positive review, package-ecosystem drift tests, and calibrated thresholds.
            """),
        ]
    )


def policy_grid(frame: pd.DataFrame) -> tuple[float, float, float, dict[str, int]]:
    train = frame[frame["split"] == "train"]
    test = frame[frame["split"] == "test"]
    classifier = RandomForestClassifier(n_estimators=260, max_depth=6, min_samples_leaf=3, class_weight="balanced", random_state=42)
    classifier.fit(train[FEATURES], train["compromised"])
    probabilities = classifier.predict_proba(test[FEATURES])[:, 1]
    labels = test["compromised"].to_numpy()
    best = None
    for review_threshold in np.arange(0.10, 0.61, 0.05):
        for block_threshold in np.arange(review_threshold + 0.10, 0.96, 0.05):
            decisions = np.where(probabilities >= block_threshold, "BLOCK", np.where(probabilities >= review_threshold, "REVIEW", "ALLOW"))
            false_allow = int(((labels == 1) & (decisions == "ALLOW")).sum())
            false_block = int(((labels == 0) & (decisions == "BLOCK")).sum())
            review_count = int((decisions == "REVIEW").sum())
            cost = 10 * false_allow + 2 * false_block + 0.45 * review_count
            if best is None or cost < best[0]:
                best = (cost, float(review_threshold), float(block_threshold), decisions)
    assert best is not None
    counts = {name: int((best[3] == name).sum()) for name in ["ALLOW", "REVIEW", "BLOCK"]}
    return best[1], best[2], best[0], counts


def build_policy_notebook(frame: pd.DataFrame) -> nbf.NotebookNode:
    review_threshold, block_threshold, cost, counts = policy_grid(frame)
    return notebook(
        [
            markdown("""
            # 03 · Human-in-the-Loop Release Policy Simulation

            Convert model probabilities into an operational **ALLOW / REVIEW / BLOCK** policy while making the error costs explicit.
            """),
            markdown(f"""
            ## tl;dr

            Under the declared synthetic cost model, the lowest-cost grid point sends scores below **{review_threshold:.2f}** to ALLOW, scores from **{review_threshold:.2f}–{block_threshold:.2f}** to REVIEW, and scores at or above **{block_threshold:.2f}** to BLOCK. On {sum(frame['split'] == 'test')} test releases this produces **{counts['ALLOW']} allow**, **{counts['REVIEW']} review**, and **{counts['BLOCK']} block** decisions at a total simulated cost of **{cost:.2f}**.
            """),
            markdown("""
            ## Context & Methods

            A single 0.5 classifier threshold hides operational trade-offs. This notebook searches two thresholds and prices three burdens:

            - Missed compromise released as ALLOW: **10 cost units**
            - Benign release incorrectly BLOCKed: **2 cost units**
            - Any manual REVIEW: **0.45 cost units**

            ### Key Assumptions

            The costs are illustrative, the test data is synthetic, and critical deterministic evidence still overrides the learned thresholds.
            """),
            markdown("## Data\n\nReuse the same fixed split and feature contract as the model notebook."),
            code(common_setup()),
            code(f"FEATURES = {FEATURES!r}\nframe = pd.read_csv(ROOT / 'data' / 'synthetic_scans.csv')\nframe.groupby(['split', 'compromised']).size().unstack(fill_value=0)"),
            markdown("## Results\n\nTrain once, score the held-out set once, and search policy thresholds without retraining."),
            code("""
from sklearn.calibration import calibration_curve
from sklearn.ensemble import RandomForestClassifier

train = frame[frame["split"] == "train"].copy()
test = frame[frame["split"] == "test"].copy()
classifier = RandomForestClassifier(
    n_estimators=260, max_depth=6, min_samples_leaf=3,
    class_weight="balanced", random_state=42,
)
classifier.fit(train[FEATURES], train["compromised"])
probability = classifier.predict_proba(test[FEATURES])[:, 1]
labels = test["compromised"].to_numpy()

rows = []
for review_threshold in np.arange(0.10, 0.61, 0.05):
    for block_threshold in np.arange(review_threshold + 0.10, 0.96, 0.05):
        decision = np.where(
            probability >= block_threshold, "BLOCK",
            np.where(probability >= review_threshold, "REVIEW", "ALLOW"),
        )
        false_allow = int(((labels == 1) & (decision == "ALLOW")).sum())
        false_block = int(((labels == 0) & (decision == "BLOCK")).sum())
        review_count = int((decision == "REVIEW").sum())
        rows.append({
            "review_threshold": round(float(review_threshold), 2),
            "block_threshold": round(float(block_threshold), 2),
            "false_allow": false_allow,
            "false_block": false_block,
            "review_count": review_count,
            "cost": 10 * false_allow + 2 * false_block + 0.45 * review_count,
        })

grid = pd.DataFrame(rows)
best = grid.sort_values(["cost", "false_allow", "review_count"]).iloc[0]
best.to_frame("value")
            """),
            code("""
pivot = grid.pivot(index="review_threshold", columns="block_threshold", values="cost")
fig, ax = plt.subplots(figsize=(10, 6))
image = ax.imshow(pivot, origin="lower", aspect="auto", cmap="Oranges")
ax.set_xticks(range(len(pivot.columns)), [f"{value:.2f}" for value in pivot.columns], rotation=60)
ax.set_yticks(range(len(pivot.index)), [f"{value:.2f}" for value in pivot.index])
ax.set_xlabel("Block threshold")
ax.set_ylabel("Review threshold")
ax.set_title("Simulated policy cost by threshold pair", loc="left", fontweight="bold")
fig.colorbar(image, ax=ax, label="Cost units")
plt.tight_layout()
plt.show()
            """),
            code("""
review_threshold = float(best["review_threshold"])
block_threshold = float(best["block_threshold"])
decision = np.where(
    probability >= block_threshold, "BLOCK",
    np.where(probability >= review_threshold, "REVIEW", "ALLOW"),
)
decision_counts = pd.Series(decision).value_counts().reindex(["ALLOW", "REVIEW", "BLOCK"], fill_value=0)
fig, ax = plt.subplots(figsize=(8.5, 4.8))
bars = ax.bar(decision_counts.index, decision_counts.values, color=[BLUE, GOLD, ORANGE], edgecolor=INK)
ax.bar_label(bars, padding=4, fontweight="bold")
ax.set_title("Held-out releases by policy decision", loc="left", fontweight="bold")
ax.set_ylabel("Release count")
ax.grid(axis="y", color=GRID)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.show()
            """),
            code("""
observed, predicted = calibration_curve(labels, probability, n_bins=8, strategy="quantile")
fig, ax = plt.subplots(figsize=(6.5, 6))
ax.plot([0, 1], [0, 1], linestyle="--", color=INK, label="Ideal calibration")
ax.plot(predicted, observed, marker="o", color=ORANGE, label="Random Forest")
ax.set_title("Probability calibration", loc="left", fontweight="bold")
ax.set_xlabel("Mean predicted probability")
ax.set_ylabel("Observed compromise rate")
ax.grid(color=GRID)
ax.legend(frameon=False)
plt.tight_layout()
plt.show()
            """),
            markdown(f"""
            ## Takeaways

            1. A review band preserves human judgment for ambiguous scores instead of pretending every probability is a binary fact.
            2. The illustrative optimum is **review ≥ {review_threshold:.2f}** and **block ≥ {block_threshold:.2f}**, but production costs must come from security and release owners.
            3. Digest mismatch, unsigned provenance, and equivalent hard controls should remain policy overrides even when the model is uncertain.
            """),
        ]
    )


def main() -> None:
    frame = pd.read_csv(ROOT / "data" / "synthetic_scans.csv")
    outputs = {
        "01_sbom_dependency_risk.ipynb": build_sbom_notebook(),
        "02_ci_cd_compromise_ml.ipynb": build_ml_notebook(frame),
        "03_release_policy_simulation.ipynb": build_policy_notebook(frame),
    }
    for filename, document in outputs.items():
        nbf.write(document, ROOT / "notebooks" / filename)
        print(f"wrote notebooks/{filename}")


if __name__ == "__main__":
    main()

