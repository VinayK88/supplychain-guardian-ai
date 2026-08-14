"""Command-line interface for local scans and CI policy gates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .sarif import report_to_sarif
from .scanner import PROJECT_ROOT, scan_bundle


def scenario_paths(root: Path, scenario: str) -> tuple[Path, Path, Path]:
    suffix = "secure" if scenario == "secure" else "compromised"
    attestation = "valid" if scenario == "secure" else "tampered"
    return (
        root / "data" / "sboms" / f"{suffix}.cdx.json",
        root / "data" / "workflows" / f"{suffix}.yml",
        root / "data" / "attestations" / f"{attestation}.json",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="supplychain-guardian",
        description="Explainable SBOM, CI/CD, and artifact-provenance risk analysis.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="Scan a fixture or custom bundle")
    scan_parser.add_argument("--scenario", choices=["secure", "compromised"], default=None)
    scan_parser.add_argument("--sbom", type=Path)
    scan_parser.add_argument("--workflow", type=Path)
    scan_parser.add_argument("--attestation", type=Path)
    scan_parser.add_argument("--output", type=Path)
    scan_parser.add_argument("--sarif", type=Path)
    scan_parser.add_argument("--fail-on-block", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.scenario:
        sbom, workflow, attestation = scenario_paths(PROJECT_ROOT, args.scenario)
        scenario = args.scenario
    else:
        supplied = [args.sbom, args.workflow, args.attestation]
        if not all(supplied):
            raise SystemExit("Provide --scenario or all of --sbom, --workflow, and --attestation")
        sbom, workflow, attestation = supplied
        scenario = "custom"
    report = scan_bundle(sbom, workflow, attestation, scenario=scenario)
    payload = json.dumps(report.to_dict(), indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    if args.sarif:
        args.sarif.parent.mkdir(parents=True, exist_ok=True)
        args.sarif.write_text(json.dumps(report_to_sarif(report), indent=2) + "\n", encoding="utf-8")
    return 2 if args.fail_on_block and report.decision == "BLOCK" else 0


if __name__ == "__main__":
    raise SystemExit(main())

