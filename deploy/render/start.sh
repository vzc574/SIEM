#!/bin/sh
# Render entrypoint: the API and the worker share one container, because a
# Render disk can only be attached to a single service.
set -e
DB=data/siem.db
if [ "${SIEM_DEMO_DATA:-0}" = 1 ] && [ ! -f "$DB" ]; then
    python video-demo/prepare.py --data-dir data --no-users
fi
python database.py init "$DB"
if [ -n "${SIEM_ADMIN_PASSWORD:-}" ]; then
    # On a persistent disk the user already exists: then apply the current password.
    printf '%s\n' "$SIEM_ADMIN_PASSWORD" | python database.py user-add "${SIEM_ADMIN_USER:-admin}" \
        --role admin --password-stdin --database "$DB" 2>/dev/null \
    || printf '%s\n' "$SIEM_ADMIN_PASSWORD" | python database.py user-passwd "${SIEM_ADMIN_USER:-admin}" \
        --password-stdin --database "$DB"
fi
python -m siem worker data/events.jsonl --output data/all-alerts.jsonl --state data/worker-state.json \
    --incident-database "$DB" --report reports/current.md --interval 30 &
exec python app.py serve --host 0.0.0.0 --port "${PORT:-10000}" --database "$DB" \
    --alerts data/all-alerts.jsonl --ingest-file data/events.jsonl
