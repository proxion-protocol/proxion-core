"""proxion-core EI0 reference library."""

__version__ = "0.1.0"

from .attenuation import derive_token
from .caveats import ip_allowlist, nonce_matches, time_window
from .context import Caveat, RequestContext
from .errors import AttenuationError, ProxionError, TicketError, TokenError, ValidationError
from .tickets import mint_ticket, redeem_ticket
from .tokens import Token, issue_token, token_canonical_bytes, verify_integrity
from .revocation import RevocationList
from .validator import ALLOW, Decision, validate_request

__all__ = [
    "ALLOW",
    "AttenuationError",
    "Caveat",
    "Decision",
    "ProxionError",
    "RequestContext",
    "TicketError",
    "Token",
    "TokenError",
    "RevocationList",
    "ValidationError",
    "derive_token",
    "issue_token",
    "ip_allowlist",
    "mint_ticket",
    "nonce_matches",
    "redeem_ticket",
    "token_canonical_bytes",
    "time_window",
    "validate_request",
    "verify_integrity",
]
