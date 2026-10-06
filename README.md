# SIME / SIEM

A defensive security information and event management platform for collecting
logs, detecting suspicious activity, analyzing malware safely, and producing
evidence-based incident reports.

## Current status

The repository is a runnable MVP with CLI, local API, dashboard, event storage,
rule and correlation detection, static file triage, quarantine workflow,
incident auditing, local IOC matching, and optional AI reporting.

For production deployment requirements and limitations, see [SECURITY.md](SECURITY.md).

## Foundation status

This repository currently contains the first foundation milestone:

- modular Python package layout;
- environment-based configuration;
- normalized security-event model;
- JSON-line event storage prototype;
- JSON-lines log collector with validation;
- explainable rule-based detection and alert generation;
- non-executing static file analysis and indicator classification;
- explicit dry-run quarantine with an audit manifest;
- deterministic evidence-based incident reports;
- indexed SQLite event storage and search;
- read-only Linux syslog ingestion;
- cross-event correlation for login patterns;
- local read-only REST API;
- optional AI-assisted reporting with bounded evidence;
- local threat-intelligence indicator matching;
- sandbox job handoff without local execution;
- portable Windows Event Log JSON ingestion;
- UFW firewall and web access-log ingestion;
- automated batch processing pipeline;
- tests for event validation and storage.

Malware analysis and response actions will be added in later phases. Any
analysis of suspicious files must run in an isolated lab or sandbox. The AI
reporting layer will summarize collected evidence and will not execute files or
make unsupervised destructive changes.

## Layout

```text
src/siem/
  api/         API boundary (future dashboard/backend endpoints)
  config/      application configuration
  domain/      core security entities and validation
  ingestion/   log collectors and parsers
  storage/     event persistence
tests/         automated tests
```

## Run tests

```bash
python3 -m unittest discover -s tests -v
```

The collector accepts records containing `source`, `event_type` (or `type`),
`message`, and an optional ISO-8601 `timestamp`/`observed_at`, `severity`, and
`host`. Unknown fields are retained under `attributes`.

## Ingest a log file

```bash
PYTHONPATH=src python3 -m siem ingest-jsonl logs/sample.jsonl \
  --source workstation-01 \
  --output data/events.jsonl
```

The command exits with status `1` and reports the line location if the input
contains malformed or invalid records.

## Run detection

```bash
PYTHONPATH=src python3 -m siem detect data/events.jsonl \
  --output data/alerts.jsonl
```

The initial rules detect high/critical events, suspicious event types, and
failed login attempts. Each alert includes its rule, reason, evidence, and a
recommended investigative action.

## Analyze a file safely

```bash
PYTHONPATH=src python3 -m siem analyze-file sample.bin \
  --output data/file-analysis.json
```

Static analysis reads the file only. It reports a hash, metadata, magic bytes,
entropy, bounded printable strings, and explainable indicators. A suspicious
classification is a triage result, not proof that a file is malware.

## Quarantine a file

Preview the action first:

```bash
PYTHONPATH=src python3 -m siem quarantine suspicious.bin
```

Apply it only after review:

```bash
PYTHONPATH=src python3 -m siem quarantine suspicious.bin --apply
```

Applied actions move the file into a generated unique name and append the
original path, destination, timestamp, and hash to `quarantine/manifest.jsonl`.

## Generate a report

```bash
PYTHONPATH=src python3 -m siem report data/alerts.jsonl \
  --analysis data/file-analysis.json \
  --output reports/incident.md
```

The report generator is deterministic and evidence-based. Its structured
context is ready for an optional AI summarization adapter in a later step.

## Optional AI report

Install the optional dependency and configure an API key:

```bash
python3 -m pip install -e '.[ai]'
export OPENAI_API_KEY='your-key'
PYTHONPATH=src python3 -m siem ai-report data/alerts.jsonl \
  --analysis data/file-analysis.json \
  --output reports/ai-incident.md
```

The integration sends bounded text evidence through the OpenAI Responses API
with response storage disabled in the request. It does not upload the original
file or execute it. Human review remains required for conclusions and actions.

## Local threat intelligence

```bash
PYTHONPATH=src python3 -m siem ioc-add sha256 abc123 \
  --source analyst --confidence 90
PYTHONPATH=src python3 -m siem ioc-scan-events data/events.jsonl
```

Indicators are stored locally with type, source, and confidence. The initial
matcher supports hashes, IPs, domains, and URLs found in event attributes.

Optional hash reputation lookup:

```bash
export VIRUSTOTAL_API_KEY='your-key'
PYTHONPATH=src python3 -m siem vt-hash <sha256>
```

This sends only the hash to VirusTotal and never uploads or downloads the
sample. See the [VirusTotal file report API](https://docs.virustotal.com/reference/file-info).

## Run the processing pipeline

```bash
PYTHONPATH=src python3 -m siem process data/events.jsonl \
  --ioc-database data/threat-intel.db \
  --output data/all-alerts.jsonl
```

The pipeline runs rule detection, cross-event correlation, and local IOC
matching in one repeatable operation. It can be scheduled with a service
manager or cron after deployment review.

The continuous worker uses `data/worker-state.json` as a durable line
checkpoint and appends only alerts generated from newly observed input lines.
Checkpoint writes are atomic, and alert fingerprints prevent duplicate output
when a process restarts after writing alerts but before checkpointing.
It can also create audited incidents and refresh a deterministic report each
cycle:

```bash
PYTHONPATH=src python3 -m siem worker data/events.jsonl \
  --ioc-database data/threat-intel.db \
  --incident-database data/siem.db \
  --report reports/current.md --interval 30
```

Use `--format syslog`, `--format windows-json`, `--format ufw`, or
`--format access` to process those raw log formats directly. The worker keeps
the same durable line checkpoint for all formats.

If `VIRUSTOTAL_API_KEY` is configured, the worker can enrich up to ten unique
SHA-256 hashes per cycle. Results are cached locally for 24 hours, failed
lookups are retried, and only hashes—not files—are sent externally:

```bash
export VIRUSTOTAL_API_KEY='your-key'
PYTHONPATH=src python3 -m siem worker data/events.jsonl \
  --external-cache data/external-intel-cache.json \
  --external-max-hashes 10
```

Fresh alerts can optionally be delivered to an operator-controlled webhook:

```bash
PYTHONPATH=src python3 -m siem worker data/events.jsonl \
  --webhook-url https://alerts.example.invalid/siem \
  --webhook-token "$SIEM_WEBHOOK_TOKEN"
```

Webhook delivery uses bounded retries and does not remove alerts from the
append-only alert file if delivery fails.

## Back up the event database

```bash
PYTHONPATH=src python3 -m siem backup-db data/siem.db backups/siem.db
```

The backup uses SQLite's consistent backup API and creates missing destination
directories.

Verify a database or backup:

```bash
PYTHONPATH=src python3 -m siem verify-db backups/siem.db
```

The command checks SQLite integrity and confirms the event, incident, and audit
tables exist.

## Event retention

Preview first:

```bash
PYTHONPATH=src python3 -m siem prune-events data/siem.db \
  --older-than-days 90
```

Apply with a backup:

```bash
PYTHONPATH=src python3 -m siem prune-events data/siem.db \
  --older-than-days 90 --apply --backup backups/pre-retention.db
```

Only security events are removed; incidents and audit history are preserved.

For continuous operation:

```bash
PYTHONPATH=src python3 -m siem worker data/events.jsonl \
  --ioc-database data/threat-intel.db --interval 30
```

Stop the worker with Ctrl+C. For production, run it under a supervisor such as
systemd or a container orchestrator.

## Submit to an isolated sandbox

```bash
PYTHONPATH=src python3 -m siem sandbox-submit suspicious.bin
```

This creates a pending job in `data/sandbox/jobs.jsonl` and does not execute or
copy the sample. To explicitly place a copy in the spool for an approved
external sandbox worker:

```bash
PYTHONPATH=src python3 -m siem sandbox-submit suspicious.bin --spool-sample
```

The external worker must enforce VM isolation, network controls, sample
retention, and signed result ingestion before this becomes dynamic analysis.

Ingest a result from that worker after validating the submitted hash:

```bash
PYTHONPATH=src python3 -m siem sandbox-ingest-result result.json \
  --sha256 <submitted-sha256> \
  --output data/sandbox-events.jsonl
```

Set `SANDBOX_RESULT_KEY` or pass `--signing-key` when the worker signs result
payloads with HMAC-SHA256.

## Import Windows Event Logs

Export Windows events as newline-delimited JSON and run:

```bash
PYTHONPATH=src python3 -m siem ingest-windows-json windows-events.jsonl \
  --output data/events.jsonl
```

The parser recognizes common `Event.System`, `EventData`, provider, computer,
event ID, and timestamp fields.

## Import network logs

```bash
PYTHONPATH=src python3 -m siem ingest-network /var/log/ufw.log \
  --format ufw --output data/events.jsonl
PYTHONPATH=src python3 -m siem ingest-network /var/log/nginx/access.log \
  --format access --output data/events.jsonl
```

## Container deployment

```bash
cp .env.example .env
# Edit .env and set a strong SIEM_API_KEY.
docker compose up --build -d
```

The API is then available at `http://127.0.0.1:8080/`.

## HTTPS deployment

For network deployment, keep the SIEM service private and put Nginx in front
of it. Place a valid certificate at `deploy/certs/fullchain.pem` and its key at
`deploy/certs/privkey.pem`, then start the secure overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.secure.yml up --build -d
```

The overlay redirects HTTP to HTTPS, enables TLS 1.2/1.3, adds HSTS, and
applies a reverse-proxy request limit. Do not commit private keys.

## Index and search events

```bash
PYTHONPATH=src python3 -m siem index-events data/events.jsonl
PYTHONPATH=src python3 -m siem search --text login --severity medium
```

Search parameters are bound through SQLite query parameters.

## Import Linux syslog

```bash
PYTHONPATH=src python3 -m siem ingest-syslog /var/log/auth.log \
  --output data/events.jsonl
```

The collector reads the source file only and normalizes supported RFC 3164
records into the common event format.

## Correlate events

```bash
PYTHONPATH=src python3 -m siem correlate data/events.jsonl \
  --output data/correlation-alerts.jsonl
```

The initial correlation rules detect repeated failed logins and successful
logins following repeated failures within a five-minute window.

## Start the API

```bash
PYTHONPATH=src python3 -m siem serve --database data/siem.db
```

Available read-only endpoints:

- `GET /health`
- `GET /metrics` (authenticated Prometheus text)
- `GET /` (browser dashboard)
- `GET /events?text=login&severity=high&limit=100`
- `GET /alerts?severity=high&limit=100`
- `GET /incidents?status=open`
- `GET /incidents/<incident-id>`
- `POST /incidents`
- `PATCH /incidents/<incident-id>`

The development API binds to localhost by default. Authentication and
authorization are required before exposing it to a network. Configure an API
key through the environment:

```bash
export SIEM_API_KEY='use-a-long-random-secret'
PYTHONPATH=src python3 -m siem serve --host 0.0.0.0
```

Authenticated requests may use `X-API-Key` or `Authorization: Bearer <key>`.
The health endpoint remains public for monitoring.

For role-based access, configure `SIEM_API_KEYS` as comma-separated
`key=role` pairs. Supported roles are `viewer`, `analyst`, and `admin`.
Viewer keys can read data; analyst and admin keys can create or update
incidents.

Open `http://127.0.0.1:8080/` in a browser to view the dashboard. The current
dashboard is intentionally lightweight and is intended for local MVP use.

Provide alert files when starting the API:

```bash
PYTHONPATH=src python3 -m siem serve \
  --alerts data/alerts.jsonl \
  --alerts data/correlation-alerts.jsonl
```

Incident creation and updates require authentication. Include `X-Actor` to
identify the analyst making the change; all lifecycle changes are written to
the SQLite audit log.

## Configuration

The application reads these optional environment variables:

- `SIEM_DATA_DIR` — event storage directory; defaults to `./data`.
- `SIEM_LOG_LEVEL` — logging level; defaults to `INFO`.
