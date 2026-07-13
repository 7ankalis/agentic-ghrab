"""Turns a Pydantic schema into a strict "JSON only" instruction.

Used by adapters whose vendor SDK doesn't have (or isn't used with) a native
structured-output mode — they fall back to prompt-enforced JSON + the repair
loop in `repair.py`.
"""

from __future__ import annotations

from pydantic import BaseModel


def build_json_system_prompt(base_system: str, schema: type[BaseModel]) -> str:
    schema_json = schema.model_json_schema()
    return (
        f"{base_system}\n\n"
        "You must respond with ONLY a single JSON object — no prose, no markdown "
        "fences, no commentary before or after it. The JSON object must validate "
        f"against this JSON Schema:\n{schema_json}"
    )


def build_repair_prompt(original_prompt: str, bad_response: str, validation_error: str) -> str:
    return (
        f"{original_prompt}\n\n"
        "--- REPAIR REQUIRED ---\n"
        f"Your previous response was:\n{bad_response}\n\n"
        f"It failed schema validation with this error:\n{validation_error}\n\n"
        "Fix the response and resend ONLY the corrected JSON object."
    )
