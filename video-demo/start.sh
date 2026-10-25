#!/usr/bin/env bash
# Start the dashboard on the demo data. API keys are read from ../.env if present.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .env ]; then set -a; . ./.env; set +a; fi
PYTHON=python3
[ -x .venv/bin/python ] && PYTHON=.venv/bin/python
echo "VirusTotal: ${VIRUSTOTAL_API_KEY:+configured}${VIRUSTOTAL_API_KEY:-NOT configured}   AI: ${OPENAI_API_KEY:+configured}${OPENAI_API_KEY:-NOT configured}"
exec "$PYTHON" app.py serve --database video-demo/data/siem.db --port "${PORT:-8080}"
