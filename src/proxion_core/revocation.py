"""Optional in-memory revocation list with TTL entries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import threading
from typing import Dict, Optional, Union

from .tokens import Token, token_canonical_bytes


def _coerce_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _hash_token_bytes(token_bytes: bytes) -> str:
    return hashlib.sha256(token_bytes).hexdigest()


def _derive_revocation_id(token: Token) -> str:
    return _hash_token_bytes(token_canonical_bytes(token))


@dataclass(frozen=True)
class RevocationEntry:
    revoked_until: datetime


class RevocationList:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: Dict[str, RevocationEntry] = {}

    def revoke(
        self,
        token_or_token_id: Union[Token, str],
        now: datetime,
        ttl_seconds: Optional[int] = None,
    ) -> str:
        now_dt = _coerce_datetime(now)
        token_id, token_exp = self._resolve_token(token_or_token_id)
        if ttl_seconds is None:
            if token_exp is None:
                raise ValueError("ttl_seconds required when token expiration is unknown")
            revoked_until = token_exp
        else:
            if ttl_seconds <= 0:
                raise ValueError("ttl_seconds must be positive")
            revoked_until = now_dt + timedelta(seconds=ttl_seconds)
            if token_exp is not None and token_exp < revoked_until:
                revoked_until = token_exp
        with self._lock:
            self._entries[token_id] = RevocationEntry(revoked_until=revoked_until)
        return token_id

    def is_revoked(self, token_or_token_id: Union[Token, str], now: datetime) -> bool:
        now_dt = _coerce_datetime(now)
        token_id, _ = self._resolve_token(token_or_token_id)
        with self._lock:
            entry = self._entries.get(token_id)
            if entry is None:
                return False
            if now_dt >= _coerce_datetime(entry.revoked_until):
                del self._entries[token_id]
                return False
            return True

    def purge(self, now: datetime) -> int:
        now_dt = _coerce_datetime(now)
        removed = 0
        with self._lock:
            expired = [
                token_id
                for token_id, entry in self._entries.items()
                if now_dt >= _coerce_datetime(entry.revoked_until)
            ]
            for token_id in expired:
                del self._entries[token_id]
                removed += 1
        return removed

    def _resolve_token(self, token_or_token_id: Union[Token, str]) -> tuple[str, Optional[datetime]]:
        if isinstance(token_or_token_id, Token):
            return _derive_revocation_id(token_or_token_id), token_or_token_id.exp
        if isinstance(token_or_token_id, str):
            return token_or_token_id, None
        raise TypeError("token_or_token_id must be Token or str")
