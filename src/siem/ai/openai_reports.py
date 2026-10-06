"""Optional OpenAI Responses API report generation."""

import json
from typing import Any


class AIIntegrationError(RuntimeError):
    """Raised when optional AI reporting cannot be completed."""


def _sanitize(value: Any, *, depth: int = 0) -> Any:
    if depth > 5:
        return "[truncated]"
    if isinstance(value, dict):
        return {str(key): _sanitize(item, depth=depth + 1) for key, item in list(value.items())[:100]}
    if isinstance(value, list):
        return [_sanitize(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return value[:4000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:4000]


def build_ai_prompt(context: dict[str, Any]) -> str:
    safe_context = _sanitize(context)
    return (
        "You are assisting a security analyst. Write a concise incident report using only the evidence below. "
        "Separate observed facts from inferences, state uncertainty, and do not claim that a file is malware "
        "unless the evidence explicitly supports that conclusion. Include: summary, key evidence, likely impact, "
        "recommended investigation steps, and limitations. Never recommend destructive action without human approval.\n\n"
        "EVIDENCE JSON:\n" + json.dumps(safe_context, sort_keys=True)
    )


def generate_ai_report(context: dict[str, Any], *, model: str) -> str:
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise AIIntegrationError("Install the optional AI dependency with: pip install 'defensive-siem[ai]'") from exc
    try:
        client = OpenAI()
        response = client.responses.create(model=model, input=build_ai_prompt(context), store=False)
        output = getattr(response, "output_text", None)
    except Exception as exc:
        raise AIIntegrationError(f"AI report request failed: {exc}") from exc
    if not output:
        raise AIIntegrationError("AI provider returned no report text")
    return output

