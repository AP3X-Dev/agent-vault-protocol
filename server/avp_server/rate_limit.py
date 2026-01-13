from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class TokenBucket:
    capacity: float
    refill_per_sec: float
    tokens: float
    last_ts: float


class RateLimiter:
    def __init__(self) -> None:
        self._buckets: Dict[Tuple[str, str, str], TokenBucket] = {}

    def allow(self, session_id: str, service: str, operation: str, *, capacity: float, refill_per_sec: float) -> bool:
        key = (session_id, service, operation)
        now = time.time()
        b = self._buckets.get(key)
        if b is None:
            b = TokenBucket(capacity=capacity, refill_per_sec=refill_per_sec, tokens=capacity, last_ts=now)
            self._buckets[key] = b

        # refill
        elapsed = max(0.0, now - b.last_ts)
        b.tokens = min(b.capacity, b.tokens + elapsed * b.refill_per_sec)
        b.last_ts = now

        if b.tokens >= 1.0:
            b.tokens -= 1.0
            return True
        return False


rate_limiter = RateLimiter()
