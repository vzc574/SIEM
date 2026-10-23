"""SIEM-2: Database & Storage Pipeline.

Entry point for the storage module. It owns the SQLite connection, the
indexed event/incident/audit schema and its migrations, and maintenance
operations (indexing, search, backup, verification, retention).

Schema (version 2):
    security_events  event_id PK, source, event_type, message, observed_at
                     (UTC ISO-8601), severity, host, attributes_json, plus
                     generated+indexed `username` and `src_ip` columns
    incidents        incident_id PK, title, severity, status, assignee, alert_ids_json
    audit_log        append-only lifecycle history per incident

Examples:
    python database.py init data/siem.db
    python database.py index data/events.jsonl --database data/siem.db
    python database.py stats data/siem.db
    python database.py search data/siem.db --text "Failed password"
    python database.py backup data/siem.db backups/siem.db
    python database.py prune data/siem.db --older-than-days 90 [--apply --backup backups/pre.db]
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from siem.reporting.report import load_jsonl  # noqa: E402
from siem.storage.backup import backup_database  # noqa: E402
from siem.storage.retention import prune_events  # noqa: E402
from siem.storage.sqlite import SCHEMA_VERSION, SqliteEventStore, connect, to_utc  # noqa: E402
from siem.storage.verify import verify_database  # noqa: E402

__all__ = ["SCHEMA_VERSION", "SqliteEventStore", "connect", "to_utc", "open_store", "stats",
           "backup_database", "verify_database", "prune_events"]


def open_store(path: Path) -> SqliteEventStore:
    """Open (creating and migrating if needed) the SIEM database."""
    return SqliteEventStore(path)


def stats(store: SqliteEventStore, *, hours: int = 24) -> dict[str, object]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    return {
        **store.metrics(),
        "window_hours": hours,
        "severity_counts": store.severity_counts(since=since),
        "top_failed_login_ips": store.top_values("src_ip", since=since, event_type="login.failed", limit=5),
        "top_failed_login_users": store.top_values("username", since=since, event_type="login.failed", limit=5),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="database", description="SIEM database and storage pipeline")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="create or migrate a database").add_argument("database", type=Path)
    index = commands.add_parser("index", help="index normalized events JSONL")
    index.add_argument("input", type=Path)
    index.add_argument("--database", type=Path, default=Path("data/siem.db"))
    stats_parser = commands.add_parser("stats", help="counts and top pivots")
    stats_parser.add_argument("database", type=Path)
    stats_parser.add_argument("--hours", type=int, default=24)
    search = commands.add_parser("search", help="search indexed events")
    search.add_argument("database", type=Path)
    search.add_argument("--text")
    search.add_argument("--severity")
    search.add_argument("--limit", type=int, default=50)
    commands.add_parser("verify", help="integrity and schema check").add_argument("database", type=Path)
    backup = commands.add_parser("backup", help="consistent online backup")
    backup.add_argument("database", type=Path)
    backup.add_argument("output", type=Path)
    prune = commands.add_parser("prune", help="preview or apply event retention")
    prune.add_argument("database", type=Path)
    prune.add_argument("--older-than-days", type=int, required=True)
    prune.add_argument("--apply", action="store_true")
    prune.add_argument("--backup", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            open_store(args.database)
            print(f"database ready at {args.database} (schema v{SCHEMA_VERSION})")
        elif args.command == "index":
            count = open_store(args.database).append_records(load_jsonl(args.input))
            print(f"indexed {count} event(s) into {args.database} (duplicates ignored)")
        elif args.command == "stats":
            print(json.dumps(stats(open_store(args.database), hours=args.hours), indent=2, sort_keys=True))
        elif args.command == "search":
            results = open_store(args.database).search(text=args.text, severity=args.severity, limit=args.limit)
            print(json.dumps(results, indent=2, sort_keys=True))
        elif args.command == "verify":
            result = verify_database(args.database)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["valid"] else 1
        elif args.command == "backup":
            backup_database(args.database, args.output)
            print(f"backup written to {args.output}")
        elif args.command == "prune":
            count = prune_events(args.database, older_than_days=args.older_than_days, apply=args.apply, backup_path=args.backup)
            print(f"{'deleted' if args.apply else 'would delete'} {count} event(s)")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"{args.command} failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
