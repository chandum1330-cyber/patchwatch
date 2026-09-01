"""Minimal stdlib HTTP client. No requests, no urllib3, no supply chain.

Handles the three things every fetcher here needs: a real User-Agent (SOFA asks
integrators to set one), token-bucket rate limiting (NVD allows 5 requests per
rolling 30s without a key, 50 with one), and retry with backoff.
"""

from __future__ import annotations

import gzip
import json
import time
import urllib.error
import urllib.request
from collections import deque
from typing import Any

USER_AGENT = "patchwatch/1.0 (+internal security patch monitor)"

DEFAULT_TIMEOUT = 30
MAX_RETRIES = 4
RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}


class FetchError(RuntimeError):
    """Raised when a source is unreachable after all retries.

    Callers must treat this as 'unknown', never as 'nothing new'. A source that
    fails silently is indistinguishable from a quiet patch day, which is exactly
    the failure mode this pipeline exists to prevent.
    """

    def __init__(self, url: str, cause: str):
        self.url = url
        self.cause = cause
        super().__init__(f"{url}: {cause}")


class RateLimiter:
    """Sliding-window limiter. NVD's documented limit is per rolling 30 seconds."""

    def __init__(self, max_calls: int, window: float):
        self.max_calls = max_calls
        self.window = window
        self._calls: deque[float] = deque()

    def acquire(self) -> None:
        now = time.monotonic()
        while self._calls and now - self._calls[0] > self.window:
            self._calls.popleft()
        if len(self._calls) >= self.max_calls:
            sleep_for = self.window - (now - self._calls[0]) + 0.1
            if sleep_for > 0:
                time.sleep(sleep_for)
            return self.acquire()
        self._calls.append(now)


def get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    limiter: RateLimiter | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    accept: str = "*/*",
) -> bytes:
    hdrs = {
        "User-Agent": USER_AGENT,
        "Accept": accept,
        "Accept-Encoding": "gzip",
    }
    hdrs.update(headers or {})

    last_error = "unknown"
    for attempt in range(MAX_RETRIES):
        if limiter:
            limiter.acquire()
        try:
            req = urllib.request.Request(url, headers=hdrs, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return raw
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
            if exc.code not in RETRYABLE_STATUS:
                raise FetchError(url, last_error) from exc
            # Honour Retry-After when the server sends one.
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            delay = float(retry_after) if retry_after and retry_after.isdigit() else 2**attempt
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
            delay = 2**attempt

        if attempt < MAX_RETRIES - 1:
            time.sleep(min(delay, 30))

    raise FetchError(url, f"exhausted {MAX_RETRIES} attempts, last error: {last_error}")


def get_json(url: str, **kwargs: Any) -> Any:
    kwargs.setdefault("accept", "application/json")
    return json.loads(get(url, **kwargs).decode("utf-8"))


def get_text(url: str, **kwargs: Any) -> str:
    return get(url, **kwargs).decode("utf-8", errors="replace")


def post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Any:
    hdrs = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    hdrs.update(headers or {})
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw.decode("utf-8")) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:800]
        raise FetchError(url, f"HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FetchError(url, str(exc)) from exc
