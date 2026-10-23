"""SIEM-1: Log Ingestion & Collectors.

Entry point for the ingestion module. It parses Syslog, Windows Event Log
JSON, UFW, web access, and JSON-lines logs into normalized security events,
and runs a tailing agent that follows a live log file.

Examples:
    python ingestion.py ingest /var/log/auth.log --format syslog --output data/events.jsonl
    python ingestion.py agent /var/log/auth.log --format syslog --output data/events.jsonl
    SIEM_INGEST_KEY=... python ingestion.py agent /var/log/auth.log --format syslog \
        --ship-to https://siem.example.com      # remote host -> central SIEM /ingest

Windows hosts use deploy/windows/siem-collector.ps1, which posts to the same
/ingest endpoint.

sshd and Windows logon events are normalized to `login.failed` /
`login.success` with `username` and `src_ip`, which the detection engine
(SIEM-3) correlates for brute-force activity.
"""

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from siem.ingestion.agent import PollResult, follow, http_sink, poll  # noqa: E402
from siem.ingestion.formats import PARSERS, LogLineError, parse_line  # noqa: E402
from siem.storage.jsonl import JsonlEventStore  # noqa: E402

__all__ = ["PARSERS", "LogLineError", "parse_line", "ingest", "poll", "follow"]


def ingest(input_path: Path, output_path: Path, *, input_format: str, source: str, strict: bool = False) -> PollResult:
    """Import a whole log file once. Bad lines are skipped unless `strict`."""
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file does not exist: {input_path}")
    store = JsonlEventStore(output_path)
    result = PollResult()
    with input_path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                store.append(parse_line(line.strip(), input_format, source=source))
                result.events_written += 1
            except LogLineError as exc:
                if strict:
                    raise LogLineError(f"{input_path}:{line_number}: {exc}") from exc
                result.errors.append(f"{input_path}:{line_number}: {exc}")
    return result


def _report(result: PollResult) -> None:
    for error in result.errors:
        print(f"skipped: {error}", file=sys.stderr)
    if result.events_written:
        print(f"wrote {result.events_written} event(s)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ingestion", description="SIEM log ingestion and collectors")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("ingest", "import a log file once"), ("agent", "follow a live log file")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("input", type=Path)
        command.add_argument("--format", dest="input_format", choices=sorted(PARSERS), required=True)
        command.add_argument("--source", help="source label (default: input file name)")
        command.add_argument("--output", type=Path, default=Path("data/events.jsonl"))
    commands.choices["ingest"].add_argument("--strict", action="store_true", help="fail on the first bad line")
    commands.choices["agent"].add_argument("--state", type=Path, help="checkpoint file (default: <output>.<input>.state.json)")
    commands.choices["agent"].add_argument("--interval", type=float, default=5.0)
    commands.choices["agent"].add_argument("--ship-to", metavar="URL",
                                           help="send events to a SIEM's /ingest endpoint instead of --output "
                                                "(API key with the 'ingest' role in $SIEM_INGEST_KEY)")
    args = parser.parse_args(argv)
    source = args.source or args.input.name

    if args.command == "ingest":
        try:
            result = ingest(args.input, args.output, input_format=args.input_format, source=source, strict=args.strict)
        except (OSError, LogLineError) as exc:
            print(f"ingestion failed: {exc}", file=sys.stderr)
            return 1
        _report(result)
        print(f"{result.events_written} event(s) written to {args.output}, {len(result.errors)} line(s) skipped")
        return 0

    state = args.state or args.output.with_name(f"{args.output.stem}.{args.input.name}.state.json")
    sink = None
    if args.ship_to:
        api_key = os.getenv("SIEM_INGEST_KEY")
        if not api_key:
            print("--ship-to needs the ingest API key in $SIEM_INGEST_KEY", file=sys.stderr)
            return 1
        try:
            sink = http_sink(args.ship_to, api_key)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    print(f"agent following {args.input} ({args.input_format}) -> {args.ship_to or args.output}")
    try:
        follow(args.input, args.output, state, input_format=args.input_format, source=source,
               interval_seconds=args.interval, on_poll=_report, sink=sink)
    except KeyboardInterrupt:
        print("agent stopped")
    except (OSError, ValueError) as exc:
        print(f"agent failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
