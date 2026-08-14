"""Deterministic security checks that create evidence before ML ranking."""

from __future__ import annotations

import re
from typing import Any

from .models import Finding
from .parsers import component_identity, component_properties, workflow_steps


PROTECTED_PACKAGE_NAMES = {
    "fastapi",
    "flask",
    "numpy",
    "pandas",
    "pydantic",
    "requests",
    "scikit-learn",
    "torch",
}
FULL_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


def _edit_distance(left: str, right: str) -> int:
    previous = list(range(len(right) + 1))
    for left_index, left_character in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_character in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[right_index] + 1,
                    previous[right_index - 1] + (left_character != right_character),
                )
            )
        previous = current
    return previous[-1]


def _blast_radius(properties: dict[str, str]) -> int:
    services = [
        value.strip()
        for value in properties.get("guardian:reachable_services", "").split(",")
        if value.strip()
    ]
    return max(len(services), 1)


def scan_sbom(sbom: dict[str, Any]) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    components = [item for item in sbom.get("components", []) if isinstance(item, dict)]
    for index, component in enumerate(components, start=1):
        name = str(component.get("name", "")).strip()
        version = str(component.get("version", "")).strip()
        subject = component_identity(component)
        properties = component_properties(component)
        blast_radius = _blast_radius(properties)
        expected_name = properties.get("guardian:expected_name", "").strip().lower()

        nearest_name = expected_name
        if not nearest_name and name.lower() not in PROTECTED_PACKAGE_NAMES:
            candidates = [
                protected
                for protected in PROTECTED_PACKAGE_NAMES
                if _edit_distance(name.lower(), protected) == 1
            ]
            nearest_name = sorted(candidates)[0] if candidates else ""
        if nearest_name and name.lower() != nearest_name:
            findings.append(
                Finding(
                    finding_id=f"SBOM-{index:03d}-TYPOSQUAT",
                    title="Dependency name resembles a protected package",
                    severity="critical",
                    category="dependency",
                    subject=subject,
                    evidence=f"Observed '{name}' while the expected package is '{nearest_name}'.",
                    remediation="Quarantine the package, verify the publisher and lock the intended dependency.",
                    confidence=0.98,
                    blast_radius=blast_radius,
                )
            )

        if not version or version.lower() in {"latest", "*", "unversioned"}:
            findings.append(
                Finding(
                    finding_id=f"SBOM-{index:03d}-UNPINNED",
                    title="Dependency version is not pinned",
                    severity="medium",
                    category="dependency",
                    subject=subject,
                    evidence=f"Version field is '{version or 'missing'}'.",
                    remediation="Resolve and lock an immutable dependency version and hash.",
                    blast_radius=blast_radius,
                )
            )

        vulnerability = properties.get("guardian:vulnerability_severity", "").lower()
        if vulnerability in {"critical", "high"}:
            severity = "critical" if vulnerability == "critical" else "high"
            advisory = properties.get("guardian:advisory", "synthetic advisory")
            findings.append(
                Finding(
                    finding_id=f"SBOM-{index:03d}-VULNERABLE",
                    title=f"{vulnerability.title()}-severity vulnerable component",
                    severity=severity,
                    category="vulnerability",
                    subject=subject,
                    evidence=f"Fixture maps this component to {advisory} ({vulnerability}).",
                    remediation="Upgrade, remove, or isolate the component after validating reachability.",
                    blast_radius=blast_radius,
                )
            )

        maintainer_age = int(properties.get("guardian:maintainer_age_days", "9999") or 9999)
        download_spike = float(properties.get("guardian:download_spike", "1") or 1)
        if maintainer_age <= 7 and download_spike >= 10:
            findings.append(
                Finding(
                    finding_id=f"SBOM-{index:03d}-PUBLISHER",
                    title="New publisher identity coincides with a download spike",
                    severity="high",
                    category="dependency",
                    subject=subject,
                    evidence=(
                        f"Publisher age is {maintainer_age} days and the synthetic download ratio is "
                        f"{download_spike:.1f}x."
                    ),
                    remediation="Require maintainer verification and provenance before promotion.",
                    confidence=0.86,
                    blast_radius=blast_radius,
                )
            )

        if not component.get("purl"):
            findings.append(
                Finding(
                    finding_id=f"SBOM-{index:03d}-IDENTITY",
                    title="Component lacks a package URL",
                    severity="low",
                    category="sbom-quality",
                    subject=subject,
                    evidence="No purl was present, which weakens cross-tool component matching.",
                    remediation="Emit a canonical package URL in the SBOM.",
                    blast_radius=blast_radius,
                )
            )
    return findings, len(components)


def scan_workflow(workflow: dict[str, Any], raw: str = "") -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    steps = workflow_steps(workflow)
    permissions = workflow.get("permissions", "")
    if permissions == "write-all":
        findings.append(
            Finding(
                finding_id="CI-001-WRITE-ALL",
                title="Workflow grants write-all permissions",
                severity="high",
                category="ci-cd",
                subject="workflow permissions",
                evidence="Top-level permissions is set to write-all.",
                remediation="Set read-only defaults and grant narrow job-level permissions.",
                blast_radius=4,
            )
        )

    if re.search(r"(?m)^\s*pull_request_target\s*:", raw):
        findings.append(
            Finding(
                finding_id="CI-002-PR-TARGET",
                title="Privileged pull_request_target trigger is enabled",
                severity="high",
                category="ci-cd",
                subject="workflow trigger",
                evidence="The workflow runs in the base repository context for pull_request_target.",
                remediation="Use pull_request or strictly separate untrusted checkout from privileged steps.",
                blast_radius=4,
            )
        )

    jobs = workflow.get("jobs", {})
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if isinstance(job, dict) and "self-hosted" in str(job.get("runs-on", "")):
                findings.append(
                    Finding(
                        finding_id=f"CI-{str(job_name).upper()}-RUNNER",
                        title="Untrusted workflow can reach a self-hosted runner",
                        severity="medium",
                        category="ci-cd",
                        subject=str(job_name),
                        evidence=f"runs-on is configured as {job.get('runs-on')!r}.",
                        remediation="Use isolated ephemeral runners and restrict which triggers can reach them.",
                        blast_radius=3,
                    )
                )

    for step in steps:
        subject = f"{step['job']} step {step['index']}"
        uses = str(step.get("uses", ""))
        if uses and "@" in uses:
            reference = uses.rsplit("@", 1)[1]
            if not FULL_SHA_PATTERN.fullmatch(reference):
                findings.append(
                    Finding(
                        finding_id=f"CI-{step['job']}-{step['index']}-ACTION-REF",
                        title="Third-party action is not pinned to a full commit SHA",
                        severity="medium",
                        category="ci-cd",
                        subject=subject,
                        evidence=f"Action reference is {uses!r}.",
                        remediation="Pin the action to a reviewed 40-character commit SHA.",
                        blast_radius=2,
                    )
                )
        command = str(step.get("run", ""))
        if re.search(r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", command):
            findings.append(
                Finding(
                    finding_id=f"CI-{step['job']}-{step['index']}-PIPE-SHELL",
                    title="Downloaded content is piped directly to a shell",
                    severity="critical",
                    category="ci-cd",
                    subject=subject,
                    evidence="The run command executes network-fetched content without integrity verification.",
                    remediation="Download, verify a pinned digest or signature, then execute from a trusted path.",
                    blast_radius=5,
                )
            )
        if "secrets." in command:
            findings.append(
                Finding(
                    finding_id=f"CI-{step['job']}-{step['index']}-SECRET",
                    title="Secret is interpolated directly into a shell command",
                    severity="high",
                    category="ci-cd",
                    subject=subject,
                    evidence="A GitHub secret expression appears inside run:, increasing log and injection risk.",
                    remediation="Pass secrets through a narrowly scoped environment variable and avoid echoing them.",
                    blast_radius=4,
                )
            )
    return findings, len(steps)


def scan_attestation(attestation: dict[str, Any]) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    subjects = attestation.get("subject", [])
    subject = subjects[0] if isinstance(subjects, list) and subjects else {}
    artifact_name = str(subject.get("name", "unknown-artifact"))
    claimed_digest = str(subject.get("digest", {}).get("sha256", ""))
    observed_digest = str(attestation.get("observed_digest", ""))
    signature_present = bool(attestation.get("signature", {}).get("present", False))
    transparency_present = bool(attestation.get("transparency_log", {}).get("included", False))
    builder = str(attestation.get("predicate", {}).get("builder", {}).get("id", ""))
    expected_builder = str(attestation.get("policy", {}).get("expected_builder", ""))

    if not claimed_digest or not observed_digest or claimed_digest != observed_digest:
        findings.append(
            Finding(
                finding_id="PROV-001-DIGEST",
                title="Artifact digest does not match the attested subject",
                severity="critical",
                category="provenance",
                subject=artifact_name,
                evidence=f"Claimed digest {claimed_digest or 'missing'}; observed {observed_digest or 'missing'}.",
                remediation="Quarantine the artifact and rebuild it from a trusted, verified workflow.",
                blast_radius=6,
            )
        )
    if not signature_present:
        findings.append(
            Finding(
                finding_id="PROV-002-SIGNATURE",
                title="Build provenance is not signed",
                severity="high",
                category="provenance",
                subject=artifact_name,
                evidence="The demo attestation has no recorded signature.",
                remediation="Generate and verify a Sigstore-backed artifact attestation.",
                blast_radius=5,
            )
        )
    if not transparency_present:
        findings.append(
            Finding(
                finding_id="PROV-003-TRANSPARENCY",
                title="Attestation is absent from the transparency log",
                severity="high",
                category="provenance",
                subject=artifact_name,
                evidence="Transparency log inclusion is false or missing.",
                remediation="Verify inclusion and identity with the platform attestation verifier.",
                blast_radius=5,
            )
        )
    if expected_builder and builder != expected_builder:
        findings.append(
            Finding(
                finding_id="PROV-004-BUILDER",
                title="Artifact was produced by an unexpected builder identity",
                severity="high",
                category="provenance",
                subject=artifact_name,
                evidence=f"Expected {expected_builder!r}; observed {builder or 'missing'!r}.",
                remediation="Block promotion and verify repository, workflow, and OIDC identity claims.",
                blast_radius=5,
            )
        )
    return findings, artifact_name

