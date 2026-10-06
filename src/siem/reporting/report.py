"""Generate deterministic reports from collected evidence.

An external AI provider can consume the structured context later. This module
does not send evidence to any service and does not invent missing facts.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def build_context(alerts: list[dict[str, Any]], analysis: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alert_count": len(alerts),
        "alerts": alerts,
        "file_analysis": analysis,
        "limitations": [
            "This report contains only supplied evidence.",
            "A suspicious classification is not proof of malware.",
            "Recommendations require analyst validation before action.",
        ],
    }


def render_markdown(context: dict[str, Any]) -> str:
    alerts = context["alerts"]
    analysis = context.get("file_analysis")
    lines = [
        "# SIEM Incident Report",
        "",
        f"Generated: `{context['generated_at']}`",
        f"Alerts: **{context['alert_count']}**",
        "",
        "## Executive Summary",
        "",
        "This report summarizes recorded security evidence. It does not establish "
        "maliciousness without analyst validation.",
        "",
        "## Alerts",
        "",
    ]
    if not alerts:
        lines.append("No alerts were provided.")
    for index, alert in enumerate(alerts, start=1):
        lines.extend([
            f"### {index}. {alert.get('title', 'Untitled alert')}",
            f"- Severity: `{alert.get('severity', 'unknown')}`",
            f"- Rule: `{alert.get('rule_id', 'unknown')}`",
            f"- Reason: {alert.get('reason', 'Not provided')}",
            f"- Recommended action: {alert.get('recommended_action', 'Review evidence')}",
            "",
        ])
    if analysis:
        lines.extend([
            "## File Analysis",
            "",
            f"- Classification: `{analysis.get('classification', 'unknown')}`",
            f"- SHA-256: `{analysis.get('sha256', 'unknown')}`",
            f"- Magic: `{analysis.get('magic', 'unknown')}`",
            f"- Indicators: {', '.join(analysis.get('indicators', [])) or 'None recorded'}",
            "",
        ])
    lines.extend([
        "## Limitations",
        "",
        *[f"- {item}" for item in context["limitations"]],
        "",
    ])
    return "\n".join(lines)


def generate_report(alert_path: Path, output_path: Path, analysis_path: Path | None = None) -> dict[str, Any]:
    alerts = load_jsonl(alert_path)
    analysis = None
    if analysis_path:
        analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    context = build_context(alerts, analysis)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown(context), encoding="utf-8")
    return context

