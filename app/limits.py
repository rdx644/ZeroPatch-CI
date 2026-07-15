"""Small dependency-free request limiter for single-instance deployments."""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request


class RateLimiter:
    def __init__(self) -> None:
        self.limit = int(os.getenv("ZEROPATCH_RATE_LIMIT", "60"))
        self.window = int(os.getenv("ZEROPATCH_RATE_WINDOW_SECONDS", "60"))
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, request: Request) -> None:
        host = request.client.host if request.client else "unknown"
        now = time.monotonic()
        hits = self._hits[host]
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            raise HTTPException(status_code=429, detail="Too many requests. Try again shortly.", headers={"Retry-After": str(self.window)})
        hits.append(now)
