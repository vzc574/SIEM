"""SIEM-4: Dashboard UI & Reporting.

Entry point for the web module: the REST API and browser dashboard (live
threat metrics, analyst triage, incident workflow, event search) and the
Markdown incident report.

Examples:
    python app.py serve --database data/siem.db --alerts data/all-alerts.jsonl
    python app.py report --alerts data/all-alerts.jsonl --output reports/current.md

Endpoints: GET / (dashboard), /health, /me, /metrics, /stats, /events,
/alerts, /incidents, /incidents/<id>; POST /login, /logout, /incidents,
/ingest (collectors; keys with role "ingest"); PATCH /incidents/<id>.

Authentication: dashboard users (`python database.py user-add NAME --role
analyst`, then sign in on the page) and/or API keys for scripts: SIEM_API_KEY
(single admin key) or SIEM_API_KEYS as `name:key=role,...` with roles
viewer/analyst/admin. The user or key name is what the incident audit log
records as the actor. The server refuses to start without credentials unless
`--insecure-local` is given with a loopback host. Behind a reverse proxy, set
SIEM_TRUSTED_PROXIES (CIDRs) so rate limiting uses the real client address.
"""

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from siem.api.server import create_server  # noqa: E402
from siem.reporting.report import generate_report  # noqa: E402

__all__ = ["create_server", "generate_report", "main"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app", description="SIEM dashboard, API and reporting")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="start the API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--database", type=Path, default=Path("data/siem.db"))
    serve.add_argument("--alerts", type=Path, action="append", help="alert JSONL file (repeatable; default data/all-alerts.jsonl)")
    serve.add_argument("--ingest-file", type=Path,
                       help="enable POST /ingest for collectors, appending events here (the worker's input)")
    serve.add_argument("--insecure-local", action="store_true",
                       help="allow anonymous admin access (only with a loopback --host; development only)")
    report = commands.add_parser("report", help="write a Markdown incident report from alerts")
    report.add_argument("--alerts", type=Path, default=Path("data/all-alerts.jsonl"))
    report.add_argument("--analysis", type=Path, help="optional static-analysis JSON")
    report.add_argument("--output", type=Path, default=Path("reports/current.md"))
    args = parser.parse_args(argv)

    if args.command == "report":
        try:
            context = generate_report(args.alerts, args.output, args.analysis)
        except (OSError, ValueError) as exc:
            print(f"report failed: {exc}", file=sys.stderr)
            return 1
        print(f"report with {context['alert_count']} alert(s) written to {args.output}")
        return 0

    alerts = args.alerts or [Path("data/all-alerts.jsonl")]
    try:
        server = create_server(args.host, args.port, args.database, os.getenv("SIEM_API_KEY"), alerts,
                               allow_insecure_local=args.insecure_local, ingest_path=args.ingest_file)
    except (OSError, ValueError) as exc:
        print(f"startup failed: {exc}", file=sys.stderr)
        return 1
    print(f"SIEM dashboard on http://{args.host}:{server.server_address[1]}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
