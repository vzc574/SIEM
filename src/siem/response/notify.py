"""Optional outbound alert notification delivery: webhook, Slack, Telegram, email."""

from collections import Counter
from dataclasses import dataclass, field
from email.message import EmailMessage
import json
import logging
import os
import smtplib
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from typing import Any, Callable

logger = logging.getLogger(__name__)
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class NotificationError(RuntimeError):
    """Raised when an alert notification cannot be delivered."""


def send_webhook(
    url: str,
    alerts: list[dict[str, Any]],
    *,
    token: str | None = None,
    timeout: float = 10.0,
    retries: int = 2,
    opener=urlopen,
) -> None:
    """Send a JSON alert batch to an operator-controlled webhook."""
    if not url.startswith("https://") and not url.startswith("http://127.0.0.1") and not url.startswith("http://localhost"):
        raise ValueError("webhook URL must use HTTPS except for localhost")
    if not alerts:
        return
    if retries < 0 or timeout <= 0:
        raise ValueError("invalid notification retry or timeout setting")
    body = json.dumps({"source": "siem", "alerts": alerts}, sort_keys=True).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "defensive-siem/0.1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, data=body, headers=headers, method="POST")
    last_error: Exception | None = None
    for _ in range(retries + 1):
        try:
            with opener(request, timeout=timeout) as response:
                if not 200 <= response.status < 300:
                    raise NotificationError(f"webhook returned HTTP {response.status}")
            return
        except (HTTPError, URLError, TimeoutError, OSError, NotificationError) as exc:
            last_error = exc
    raise NotificationError(f"webhook delivery failed: {last_error}") from last_error


def summarize(alerts: list[dict[str, Any]], *, max_lines: int = 10) -> tuple[str, str]:
    """(subject, body) in plain text for chat and email channels."""
    counts = Counter(str(alert.get("severity", "unknown")) for alert in alerts)
    ordered = sorted(counts, key=lambda severity: -SEVERITY_RANK.get(severity, -1))
    subject = f"SIEM: {len(alerts)} new alert(s) ({', '.join(f'{counts[s]} {s}' for s in ordered)})"
    ranked = sorted(alerts, key=lambda alert: -SEVERITY_RANK.get(str(alert.get("severity")), -1))
    lines = [f"[{str(alert.get('severity', '?')).upper()}] {alert.get('title', 'Alert')}: {alert.get('reason', '')}"
             for alert in ranked[:max_lines]]
    if len(alerts) > max_lines:
        lines.append(f"... and {len(alerts) - max_lines} more - see the SIEM dashboard.")
    return subject, "\n".join(lines)


def _post_json(url: str, payload: dict[str, Any], *, opener=urlopen, timeout: float = 10.0) -> None:
    request = Request(url, data=json.dumps(payload).encode("utf-8"), method="POST",
                      headers={"Content-Type": "application/json", "User-Agent": "defensive-siem/0.1"})
    try:
        with opener(request, timeout=timeout) as response:
            if not 200 <= response.status < 300:
                raise NotificationError(f"HTTP {response.status}")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise NotificationError(str(exc)) from exc


def send_slack(webhook_url: str, alerts: list[dict[str, Any]], *, opener=urlopen) -> None:
    """Slack (or Mattermost/Discord-compatible) incoming webhook."""
    if not webhook_url.startswith("https://"):
        raise ValueError("Slack webhook URL must use https://")
    subject, body = summarize(alerts)
    _post_json(webhook_url, {"text": f"*{subject}*\n{body}"}, opener=opener)


def send_telegram(bot_token: str, chat_id: str, alerts: list[dict[str, Any]], *, opener=urlopen) -> None:
    subject, body = summarize(alerts)
    text = f"{subject}\n\n{body}"[:4000]  # Telegram's limit is 4096 characters
    _post_json(f"https://api.telegram.org/bot{bot_token}/sendMessage",
               {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}, opener=opener)


@dataclass(frozen=True, slots=True)
class SmtpSettings:
    host: str
    port: int
    sender: str
    recipients: tuple[str, ...]
    username: str | None = None
    password: str | None = None


def send_email(settings: SmtpSettings, alerts: list[dict[str, Any]], *, smtp_factory: Callable[..., Any] | None = None) -> None:
    """Send via SMTP: implicit TLS on port 465, otherwise STARTTLS (required)."""
    subject, body = summarize(alerts, max_lines=50)
    message = EmailMessage()
    message["Subject"], message["From"], message["To"] = subject, settings.sender, ", ".join(settings.recipients)
    message.set_content(body + "\n")
    context = ssl.create_default_context()
    try:
        if smtp_factory is not None:
            client = smtp_factory(settings.host, settings.port)
        elif settings.port == 465:
            client = smtplib.SMTP_SSL(settings.host, settings.port, timeout=15, context=context)
        else:
            client = smtplib.SMTP(settings.host, settings.port, timeout=15)
        with client:
            if settings.port != 465:
                client.starttls(context=context)
            if settings.username:
                client.login(settings.username, settings.password or "")
            client.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise NotificationError(f"email delivery failed: {exc}") from exc


@dataclass(slots=True)
class Notifier:
    """Fan out fresh alerts at or above `min_severity` to every configured channel.

    Channels fail independently: a Slack outage does not stop email.
    """

    min_severity: str = "high"
    slack_webhook: str | None = None
    telegram: tuple[str, str] | None = None
    email: SmtpSettings | None = None
    opener: Any = urlopen
    smtp_factory: Callable[..., Any] | None = None
    sent: Counter = field(default_factory=Counter)

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "Notifier":
        env = os.environ if environ is None else environ
        minimum = env.get("SIEM_NOTIFY_MIN_SEVERITY", "high").lower()
        if minimum not in SEVERITY_RANK:
            raise ValueError(f"SIEM_NOTIFY_MIN_SEVERITY must be one of {', '.join(SEVERITY_RANK)}")
        telegram = None
        if env.get("SIEM_TELEGRAM_BOT_TOKEN") and env.get("SIEM_TELEGRAM_CHAT_ID"):
            telegram = (env["SIEM_TELEGRAM_BOT_TOKEN"], env["SIEM_TELEGRAM_CHAT_ID"])
        email = None
        if env.get("SIEM_SMTP_HOST") and env.get("SIEM_SMTP_TO"):
            email = SmtpSettings(
                host=env["SIEM_SMTP_HOST"], port=int(env.get("SIEM_SMTP_PORT", "587")),
                sender=env.get("SIEM_SMTP_FROM") or env.get("SIEM_SMTP_USER") or "siem@localhost",
                recipients=tuple(item.strip() for item in env["SIEM_SMTP_TO"].split(",") if item.strip()),
                username=env.get("SIEM_SMTP_USER") or None, password=env.get("SIEM_SMTP_PASSWORD") or None,
            )
        return cls(min_severity=minimum, slack_webhook=env.get("SIEM_SLACK_WEBHOOK_URL") or None, telegram=telegram, email=email)

    @property
    def channels(self) -> list[str]:
        return [name for name, enabled in (("slack", self.slack_webhook), ("telegram", self.telegram), ("email", self.email)) if enabled]

    def notify(self, alerts: list[dict[str, Any]]) -> list[str]:
        """Deliver; returns the channels that failed (already logged)."""
        threshold = SEVERITY_RANK[self.min_severity]
        selected = [alert for alert in alerts if SEVERITY_RANK.get(str(alert.get("severity")), 0) >= threshold]
        if not selected:
            return []
        senders: list[tuple[str, Callable[[], None]]] = []
        if self.slack_webhook:
            senders.append(("slack", lambda: send_slack(self.slack_webhook, selected, opener=self.opener)))
        if self.telegram:
            senders.append(("telegram", lambda: send_telegram(*self.telegram, selected, opener=self.opener)))
        if self.email:
            senders.append(("email", lambda: send_email(self.email, selected, smtp_factory=self.smtp_factory)))
        failed: list[str] = []
        for name, send in senders:
            try:
                send()
                self.sent[name] += len(selected)
            except (NotificationError, ValueError) as exc:
                logger.warning("%s notification failed: %s", name, exc)
                failed.append(name)
        return failed
