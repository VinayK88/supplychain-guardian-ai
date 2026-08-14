"""Input parsing helpers for CycloneDX-style SBOMs, workflows, and attestations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


def load_document(path: str | Path) -> tuple[dict[str, Any], str]:
    source = Path(path)
    raw = source.read_text(encoding="utf-8")
    suffix = source.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        document = yaml.safe_load(raw) or {}
    else:
        document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError(f"Expected an object at the document root: {source}")
    return document, raw


def component_properties(component: dict[str, Any]) -> dict[str, str]:
    properties: dict[str, str] = {}
    for item in component.get("properties", []):
        if isinstance(item, dict) and "name" in item:
            properties[str(item["name"])] = str(item.get("value", ""))
    return properties


def component_identity(component: dict[str, Any]) -> str:
    group = str(component.get("group", "")).strip()
    name = str(component.get("name", "unknown-component")).strip()
    version = str(component.get("version", "unversioned")).strip() or "unversioned"
    prefix = f"{group}/" if group else ""
    return f"{prefix}{name}@{version}"


def workflow_steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return steps
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for index, step in enumerate(job.get("steps", []), start=1):
            if isinstance(step, dict):
                steps.append({"job": str(job_name), "index": index, **step})
    return steps

