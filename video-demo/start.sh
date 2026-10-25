#!/usr/bin/env bash
# Start the dashboard on the demo data. API keys are read from ../.env if present.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .env ]; then set -a; . ./.env; set +a; fi
PYTHON=python3
[ -x .venv/bin/python ] && PYTHON=.venv/bin/python
state() { if [ -n "$1" ]; then echo configured; else echo "NOT configured"; fi; }
echo "VirusTotal: $(state "${VIRUSTOTAL_API_KEY:-}")   AI: $(state "${OPENAI_API_KEY:-}")${OPENAI_BASE_URL:+ (${OPENAI_BASE_URL})}"
exec "$PYTHON" app.py serve --database video-demo/data/siem.db --port "${PORT:-8080}"
