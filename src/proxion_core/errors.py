"""Error types for proxion-core EI0."""

class ProxionError(Exception):
    """Base error for Proxion core."""


class TicketError(ProxionError):
    """Ticket mint/redeem errors."""


class TokenError(ProxionError):
    """Token issuance or integrity errors."""


class AttenuationError(ProxionError):
    """Errors during token attenuation/derivation."""


class ValidationError(ProxionError):
    """Errors during RS-side validation."""
