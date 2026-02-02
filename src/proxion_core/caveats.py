"""Caveat constructors for common request-context constraints."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Optional, Set

from .context import Caveat, RequestContext


@dataclass(frozen=True)
class _SafePredicate:
    name: str

    def __call__(self, ctx: RequestContext) -> bool:
        raise NotImplementedError

    def safe_eval(self, ctx: RequestContext) -> bool:
        try:
            return bool(self(ctx))
        except Exception:
            return False


@dataclass(frozen=True)
class _IpAllowlist(_SafePredicate):
    allowed: Set[str]

    def __call__(self, ctx: RequestContext) -> bool:
        if ctx is None or ctx.ip is None:
            return False
        return ctx.ip in self.allowed


@dataclass(frozen=True)
class _TimeWindow(_SafePredicate):
    not_before: float
    not_after: float

    def __call__(self, ctx: RequestContext) -> bool:
        if ctx is None or not isinstance(ctx.now, datetime):
            return False
        now_dt = ctx.now
        if now_dt.tzinfo is None:
            now_dt = now_dt.replace(tzinfo=timezone.utc)
        ts = now_dt.timestamp()
        return self.not_before <= ts <= self.not_after


@dataclass(frozen=True)
class _NonceMatches(_SafePredicate):
    expected: str

    def __call__(self, ctx: RequestContext) -> bool:
        if ctx is None:
            return False
        return ctx.device_nonce == self.expected


def ip_allowlist(allowed: Set[str]) -> Caveat:
    name = f"ip_allowlist:{','.join(sorted(allowed))}"
    predicate = _IpAllowlist(name=name, allowed=set(allowed))
    return Caveat(id=name, predicate=predicate.safe_eval)


def time_window(not_before: float, not_after: float) -> Caveat:
    name = f"time_window:{not_before}:{not_after}"
    predicate = _TimeWindow(name=name, not_before=float(not_before), not_after=float(not_after))
    return Caveat(id=name, predicate=predicate.safe_eval)


def nonce_matches(expected: str) -> Caveat:
    name = f"nonce_matches:{expected}"
    predicate = _NonceMatches(name=name, expected=str(expected))
    return Caveat(id=name, predicate=predicate.safe_eval)
