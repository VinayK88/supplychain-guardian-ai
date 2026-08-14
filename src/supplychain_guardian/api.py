"""FastAPI service exposing the same deterministic scanner used by the CLI."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .cli import scenario_paths
from .scanner import PROJECT_ROOT, scan_bundle, scan_documents


class ScanRequest(BaseModel):
    sbom: dict[str, Any]
    workflow: dict[str, Any]
    attestation: dict[str, Any]
    workflow_raw: str = Field(default="", description="Optional source text for trigger checks")
    scenario: str = "api-request"


app = FastAPI(
    title="SupplyChain Guardian AI",
    version="0.1.0",
    description="Explainable, evidence-first software supply-chain risk scoring.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "supplychain-guardian-ai"}


@app.get("/samples/{scenario}")
def sample_scan(scenario: Literal["secure", "compromised"]) -> dict[str, Any]:
    paths = scenario_paths(PROJECT_ROOT, scenario)
    return scan_bundle(*paths, scenario=scenario).to_dict()


@app.post("/scan")
def scan(request: ScanRequest) -> dict[str, Any]:
    return scan_documents(
        request.sbom,
        request.workflow,
        request.attestation,
        workflow_raw=request.workflow_raw,
        scenario=request.scenario,
    ).to_dict()

