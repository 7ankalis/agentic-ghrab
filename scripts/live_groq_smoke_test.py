"""Manual smoke test proving the provider-agnostic AI layer works end-to-end
with a real Groq API key, routed through ModelRouter exactly the way a
future Agent 3/5/7 would call it.

Not part of the pytest suite (it costs a real API call and needs a key) —
run it directly:

    .venv/bin/python scripts/live_groq_smoke_test.py
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel

from vmc.agents.ingest import run_agent1
from vmc.providers.groq_provider import GroqProvider
from vmc.providers.retry import generate_json_with_fallback
from vmc.providers.router import ModelRouter

ROOT = Path(__file__).parent.parent
load_dotenv(ROOT / ".env")


class FindingTriageNote(BaseModel):
    one_line_summary: str
    suggested_priority: Literal["Critical", "High", "Medium", "Low"]
    rationale: str


async def main() -> None:
    csv_path = ROOT / "docs" / "sample_data" / "ghrab_vulnerabilities.csv"
    md_path = ROOT / "docs" / "sample_data" / "ghrab_architecture.md"
    findings, *_ = run_agent1(csv_path, md_path)
    zerologon = next(f for f in findings if f.cve_id == "CVE-2020-1472")

    provider_registry = {
        "groq": lambda model, temperature: GroqProvider(
            model, temperature, api_key=os.environ["GROQ_API_KEY"]
        ),
    }
    router = ModelRouter.from_yaml(ROOT / "config" / "model_router.yaml", provider_registry)
    providers = router.providers_for("threat_intel_enrichment")  # groq, per config/model_router.yaml

    result = await generate_json_with_fallback(
        providers,
        system=(
            "You are a vulnerability triage assistant. Given a finding's details, "
            "produce a one-line summary and a suggested priority band with a short rationale. "
            "Do not invent facts not present in the input."
        ),
        prompt=(
            f"Finding: {zerologon.title}\n"
            f"CVE: {zerologon.cve_id}\n"
            f"CVSS: {zerologon.cvss_score}\n"
            f"Asset: {zerologon.asset_hostname} ({zerologon.zone})\n"
            f"Description: {zerologon.description}\n"
            f"Consequence: {zerologon.consequence}"
        ),
        schema=FindingTriageNote,
        temperature=0.1,
    )
    print(f"Provider chain tried: {[p.name for p in providers]}")
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    asyncio.run(main())
