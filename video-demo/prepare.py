"""Build a fresh, realistic dataset for the recorded demo video.

Run from the repository root:  python3 video-demo/prepare.py

It writes attack logs (SSH brute force, password spraying, sudo abuse,
Windows backdoor account + log clearing, firewall port scan, web attacks),
pushes them through the real ingestion and detection modules into
video-demo/data/siem.db, creates two dashboard users, and copies the
malware samples for the upload demo into video-demo/samples/.
Timestamps are relative to now so everything shows in the "last 24 hours".
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "video-demo"
DATA, LOGS, SAMPLES = KIT / "data", KIT / "logs", KIT / "samples"
LABS = Path.home() / "Downloads/Practical Malware Analysis Labs/BinaryCollection"
DEMO_FILES = ["Chapter_10L/Lab10-01.sys", "Chapter_12L/Lab12-04.exe", "Chapter_18L/Lab18-01.exe"]
# The standard antivirus test file: harmless, but every engine detects it.
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
USERS = {"admin": "admin", "analyst": "analyst"}
PASSWORD = "SiemDemo-2026!"
NOW = datetime.now().astimezone()


def syslog_time(minutes_ago: float) -> str:
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%b %e %H:%M:%S")


def auth_log() -> list[str]:
    lines = []
    # 1. SSH brute force on root that finally succeeds: the attacker got in.
    for i in range(8):
        lines.append(f"{syslog_time(125 - i * 0.4)} web-01 sshd[{4100 + i}]: Failed password for root from 203.0.113.50 port {50100 + i} ssh2")
    lines.append(f"{syslog_time(121.5)} web-01 sshd[4120]: Accepted password for root from 203.0.113.50 port 50200 ssh2")
    # 2. Password spraying: one IP, many accounts.
    for i, user in enumerate(["admin", "test", "oracle", "postgres", "ubuntu", "git", "deploy", "backup", "ftp", "guest", "support", "www"]):
        lines.append(f"{syslog_time(300 - i * 0.2)} web-01 sshd[{5200 + i}]: Failed password for invalid user {user} from 198.51.100.23 port {41000 + i} ssh2")
    # 3. Privilege abuse with sudo.
    lines.append(f"{syslog_time(60)} web-01 sudo:      bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow")
    lines.append(f"{syslog_time(45)} web-01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash")
    # Normal activity, so it is not only attacks.
    for i in range(6):
        lines.append(f"{syslog_time(600 - i * 70)} web-01 sshd[{3000 + i}]: Accepted publickey for alice from 10.0.0.15 port {40000 + i} ssh2")
    return sorted(lines, key=lambda line: datetime.strptime(f"{NOW.year} {line[:15]}", "%Y %b %d %H:%M:%S"))


def windows_log() -> list[str]:
    def event(event_id: int, minutes_ago: float, **data: str) -> str:
        created = (NOW - timedelta(minutes=minutes_ago)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
        return json.dumps({"Event": {"System": {"EventID": event_id, "TimeCreated": created, "Computer": "WIN-DC01",
                                                "Provider": {"Name": "Microsoft-Windows-Security-Auditing"}},
                                     "EventData": {"Data": [{"Name": k, "#text": v} for k, v in data.items()]}},
                           "Message": "Security event"})
    lines = [event(4625, 95 - i * 0.3, TargetUserName="Administrator", IpAddress="192.0.2.77", LogonType="3") for i in range(6)]
    lines += [event(4624, 92, TargetUserName="Administrator", IpAddress="192.0.2.77", LogonType="10"),
              event(4720, 90, TargetUserName="svc-backup2", SubjectUserName="Administrator"),
              event(4732, 89, MemberName="svc-backup2", TargetUserName="Administrators", SubjectUserName="Administrator"),
              event(1102, 85, SubjectUserName="Administrator")]
    return lines


def ufw_log() -> list[str]:
    return [f"{syslog_time(130 - i * 0.05)} web-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.5 PROTO=TCP SPT=51515 DPT={port}"
            for i, port in enumerate([21, 23, 25, 80, 110, 135, 139, 443, 445, 3306, 3389, 5432, 5900, 8080])]


def access_log() -> list[str]:
    paths = ["/wp-login.php", "/.env", "/../../etc/passwd", "/admin", "/phpmyadmin/", "/index.php?id=1%27%20OR%201=1--", "/.git/config"]
    return [f"192.0.2.10 - - [{(NOW - timedelta(minutes=200 - i)).strftime('%d/%b/%Y:%H:%M:%S %z')}] \"GET {path} HTTP/1.1\" {403 if i % 2 else 404} 162 \"-\" \"sqlmap/1.7\""
            for i, path in enumerate(paths)]


def run(*args: str, stdin: str | None = None) -> None:
    result = subprocess.run([sys.executable, *args], cwd=ROOT, input=stdin, text=True, capture_output=True)
    print("  " + (result.stdout or result.stderr).strip().splitlines()[-1])
    if result.returncode:
        raise SystemExit(result.stderr)


def main() -> None:
    shutil.rmtree(DATA, ignore_errors=True)
    shutil.rmtree(ROOT / "cli-demo", ignore_errors=True)  # output of the command-line scene
    for directory in (DATA, LOGS, SAMPLES):
        directory.mkdir(parents=True, exist_ok=True)
    logs = {"auth.log": ("syslog", auth_log()), "windows-security.jsonl": ("windows-json", windows_log()),
            "ufw.log": ("ufw", ufw_log()), "nginx-access.log": ("access", access_log())}
    print("1. Writing attack logs to video-demo/logs/")
    for name, (_, lines) in logs.items():
        (LOGS / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("2. Ingesting (ingestion.py)")
    events = DATA / "events.jsonl"
    for name, (fmt, _) in logs.items():
        run("ingestion.py", "ingest", str(LOGS / name), "--format", fmt, "--output", str(events))
    print("3. Detecting (detector.py)")
    run("database.py", "init", str(DATA / "siem.db"))
    run("detector.py", "detect", str(events), "--output", str(DATA / "alerts.jsonl"), "--database", str(DATA / "siem.db"))
    print("4. Creating dashboard users")
    for user, role in USERS.items():
        run("database.py", "user-add", user, "--role", role, "--password-stdin", "--database", str(DATA / "siem.db"), stdin=PASSWORD + "\n")
    print("5. Preparing samples in video-demo/samples/")
    for relative in DEMO_FILES:
        source = LABS / relative
        if source.exists():
            shutil.copyfile(source, SAMPLES / source.name)
        else:
            print(f"  missing {source} (skipped)")
    (SAMPLES / "eicar-test-virus.com").write_bytes(EICAR)
    (SAMPLES / "meeting-notes.txt").write_text("Team meeting notes: release on Friday, update the docs.\n", encoding="utf-8")
    print(f"\nReady. Start the dashboard with:  ./video-demo/start.sh\n"
          f"Sign in as admin / {PASSWORD}  (or analyst / {PASSWORD})")


if __name__ == "__main__":
    main()
