import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from proxion_core.errors import TicketError
from proxion_core.tickets import mint_ticket, redeem_ticket
from proxion_core.validator import Decision


def _redeem_decision(ticket_id: str, rp_pubkey: str, now: datetime) -> Decision:
    try:
        redeem_ticket(ticket_id, rp_pubkey, now)
        return Decision(True, None)
    except TicketError:
        return Decision(False, "ticket_error")


class TicketTests(unittest.TestCase):
    def test_ticket_redeemed_twice_denies(self) -> None:
        ticket = mint_ticket(30)
        now = datetime.now(timezone.utc)
        first = _redeem_decision(ticket.ticket_id, "rp_key", now)
        second = _redeem_decision(ticket.ticket_id, "rp_key", now)
        self.assertTrue(first.allowed)
        self.assertFalse(second.allowed)

    def test_ticket_expired_denies(self) -> None:
        ticket = mint_ticket(1)
        expired_at = ticket.expires_at + timedelta(seconds=1)
        decision = _redeem_decision(ticket.ticket_id, "rp_key", expired_at)
        self.assertFalse(decision.allowed)


if __name__ == "__main__":
    unittest.main()
