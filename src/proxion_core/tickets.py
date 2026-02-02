"""Permission ticket minting and redemption."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import secrets
import threading
from typing import Dict, Optional

from .errors import TicketError


@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    expires_at: datetime


def _coerce_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class _TicketStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: Dict[str, Dict[str, object]] = {}

    def mint(self, ttl_seconds: int, now: Optional[datetime] = None) -> Ticket:
        if ttl_seconds <= 0:
            raise TicketError("ttl_seconds must be positive")
        now_dt = _coerce_datetime(now or datetime.now(timezone.utc))
        ticket_id = secrets.token_urlsafe(24)
        expires_at = now_dt + timedelta(seconds=ttl_seconds)
        with self._lock:
            self._store[ticket_id] = {
                "expires_at": expires_at,
                "redeemed": False,
                "rp_pubkey": None,
            }
        return Ticket(ticket_id=ticket_id, expires_at=expires_at)

    def redeem(self, ticket_id: str, rp_pubkey: str, now: datetime) -> bool:
        now_dt = _coerce_datetime(now)
        with self._lock:
            record = self._store.get(ticket_id)
            if record is None:
                raise TicketError("ticket not found")
            expires_at = record["expires_at"]
            if not isinstance(expires_at, datetime):
                raise TicketError("ticket store corrupted")
            if now_dt >= _coerce_datetime(expires_at):
                del self._store[ticket_id]
                raise TicketError("ticket expired")
            if record["redeemed"]:
                raise TicketError("ticket already redeemed")
            record["redeemed"] = True
            record["rp_pubkey"] = rp_pubkey
            return True


_STORE = _TicketStore()


def mint_ticket(ttl_seconds: int) -> Ticket:
    return _STORE.mint(ttl_seconds=ttl_seconds)


def redeem_ticket(ticket_id: str, rp_pubkey: str, now: datetime) -> bool:
    return _STORE.redeem(ticket_id=ticket_id, rp_pubkey=rp_pubkey, now=now)
