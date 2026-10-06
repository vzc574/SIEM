"""Optional outbound alert notification delivery."""

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from typing import Any


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
