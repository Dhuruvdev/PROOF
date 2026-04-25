"""Anti-abuse middleware: per-IP token-bucket rate limiting + body-size cap.

In-process — no Redis dependency. Buckets are keyed by the requester's IP
(prefers the leftmost X-Forwarded-For when running behind a trusted reverse
proxy such as Replit's edge, falls back to the socket peer). Buckets are
purged opportunistically every ``_PURGE_INTERVAL`` seconds so memory use
stays bounded under a sustained attack.

Limits are configured per-route prefix; unmatched routes are unrestricted.
Returning 429 with a real ``Retry-After`` header, and 413 for oversized
bodies, are the standard production responses both Cloudflare's edge and
nginx's ``limit_req_zone`` use, so existing ops tooling Just Works.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Callable

from fastapi import Request
from fastapi.responses import JSONResponse, Response


# --------------------------------------------------------------------------- #
# Token bucket
# --------------------------------------------------------------------------- #


@dataclass
class _Bucket:
    tokens: float
    updated_at: float


@dataclass
class RateRule:
    """One bucket spec.  ``capacity`` tokens, refilled at ``refill_per_s``/s."""
    capacity: float
    refill_per_s: float

    @classmethod
    def per_minute(cls, n: int) -> "RateRule":
        return cls(capacity=float(n), refill_per_s=n / 60.0)


class TokenBucketLimiter:
    """Thread-safe token bucket keyed by (ip, scope)."""

    _PURGE_INTERVAL = 60.0
    _MAX_KEYS = 50_000   # hard cap so a flood of unique IPs can't OOM us

    def __init__(self) -> None:
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._lock = Lock()
        self._last_purge = time.monotonic()

    def check(self, key: tuple[str, str], rule: RateRule, cost: float = 1.0,
              now: float | None = None) -> tuple[bool, float]:
        """Returns (allowed, retry_after_seconds)."""
        t = time.monotonic() if now is None else now
        with self._lock:
            self._maybe_purge_locked(t)
            b = self._buckets.get(key)
            if b is None:
                if len(self._buckets) >= self._MAX_KEYS:
                    # Last-resort eviction: drop the oldest 10% of buckets.
                    items = sorted(self._buckets.items(), key=lambda kv: kv[1].updated_at)
                    for k, _ in items[: max(1, self._MAX_KEYS // 10)]:
                        self._buckets.pop(k, None)
                b = _Bucket(tokens=rule.capacity, updated_at=t)
                self._buckets[key] = b
            else:
                # Refill since last touch.
                elapsed = max(0.0, t - b.updated_at)
                b.tokens = min(rule.capacity, b.tokens + elapsed * rule.refill_per_s)
                b.updated_at = t

            if b.tokens >= cost:
                b.tokens -= cost
                return True, 0.0

            need = cost - b.tokens
            retry = need / rule.refill_per_s if rule.refill_per_s > 0 else 60.0
            return False, retry

    def _maybe_purge_locked(self, now: float) -> None:
        if now - self._last_purge < self._PURGE_INTERVAL:
            return
        self._last_purge = now
        # Drop buckets that are full and untouched for >= 5 minutes.
        cutoff = now - 300.0
        for k, b in list(self._buckets.items()):
            if b.updated_at < cutoff:
                self._buckets.pop(k, None)


# --------------------------------------------------------------------------- #
# Public middleware
# --------------------------------------------------------------------------- #


@dataclass
class _RouteRule:
    prefix: str
    methods: tuple[str, ...]
    rule: RateRule
    scope: str
    max_body_bytes: int | None = None


class AbuseGuard:
    """Compose into a FastAPI app via ``app.middleware('http')(guard)``."""

    def __init__(self) -> None:
        self.limiter = TokenBucketLimiter()
        self._rules: list[_RouteRule] = []

    def add(self, prefix: str, methods: tuple[str, ...], rule: RateRule,
            *, scope: str | None = None, max_body_bytes: int | None = None) -> None:
        self._rules.append(_RouteRule(
            prefix=prefix, methods=tuple(m.upper() for m in methods),
            rule=rule, scope=scope or prefix,
            max_body_bytes=max_body_bytes,
        ))

    def _match(self, method: str, path: str) -> _RouteRule | None:
        for r in self._rules:
            if method == "OPTIONS":
                continue   # never throttle CORS preflights
            if method not in r.methods:
                continue
            if path == r.prefix or path.startswith(r.prefix.rstrip("/") + "/"):
                return r
        return None

    @staticmethod
    def client_ip(request: Request) -> str:
        # Prefer the leftmost X-Forwarded-For (the original client). Replit's
        # edge proxy sets this header to the visitor's real IP. Fall back to
        # the socket peer for direct hits.
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            ip = xff.split(",", 1)[0].strip()
            if ip:
                return ip
        client = request.client
        return (client.host if client else "0.0.0.0") or "0.0.0.0"

    async def __call__(self, request: Request, call_next: Callable):
        rule = self._match(request.method, request.url.path)
        if rule is None:
            return await call_next(request)

        # Body-size cap (cheap header check first; real check is enforced by
        # the route handler reading via _bounded_json_body() for streaming
        # clients that omit Content-Length).
        if rule.max_body_bytes is not None:
            cl = request.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > rule.max_body_bytes:
                return JSONResponse(
                    {"error": "payload-too-large",
                     "max_bytes": rule.max_body_bytes},
                    status_code=413,
                )

        ip = self.client_ip(request)
        ok, retry = self.limiter.check((ip, rule.scope), rule.rule)
        if not ok:
            retry_int = max(1, int(retry + 0.5))
            return JSONResponse(
                {"error": "rate-limited",
                 "scope": rule.scope,
                 "retry_after_seconds": retry_int},
                status_code=429,
                headers={"Retry-After": str(retry_int)},
            )

        return await call_next(request)


async def bounded_json_body(request: Request, max_bytes: int) -> bytes:
    """Read the request body but refuse anything over ``max_bytes``.

    Catches streaming clients that send a body without Content-Length (or
    lie about it). Returns the raw bytes; raise 413 by raising HTTPException
    in the caller after seeing a None-equivalent.
    """
    received = 0
    chunks: list[bytes] = []
    async for chunk in request.stream():
        received += len(chunk)
        if received > max_bytes:
            raise _PayloadTooLarge(max_bytes)
        chunks.append(chunk)
    return b"".join(chunks)


class _PayloadTooLarge(Exception):
    def __init__(self, limit: int) -> None:
        super().__init__(f"body exceeds {limit} bytes")
        self.limit = limit


def payload_too_large_response(exc: _PayloadTooLarge) -> Response:
    return JSONResponse(
        {"error": "payload-too-large", "max_bytes": exc.limit},
        status_code=413,
    )


# Re-exported under a stable name so callers don't import from a private path.
PayloadTooLarge = _PayloadTooLarge
