"""RS-side validation for capability tokens."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .context import RequestContext
from .tokens import Token, verify_integrity
from .revocation import RevocationList


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: Optional[str] = None


ALLOW = Decision(True, None)


def _deny(reason: str) -> Decision:
    return Decision(False, reason)


def _default_pop_check(token: Token, proof: object) -> bool:
    if not isinstance(proof, dict):
        return False
    # Support both for compatibility
    proof_key = proof.get("holder_key_fingerprint") or proof.get("pubkey")
    return proof_key == token.holder_key_fingerprint


def validate_request(
    token: Token,
    ctx: RequestContext,
    proof: object,
    signing_key: bytes,
    revocation_list: Optional[RevocationList] = None,
    proof_verifier: Optional[Callable[[Token, RequestContext, object], bool]] = None,
) -> Decision:
    try:
        if revocation_list is not None:
            try:
                if revocation_list.is_revoked(token, ctx.now):
                    return _deny("revoked")
            except Exception:
                return _deny("revocation_error")
        verify_integrity(token, signing_key)
        if ctx.now >= token.exp:
            return _deny("expired")
        if token.aud != ctx.aud:
            return _deny("audience_mismatch")
        if proof_verifier is not None:
            if not proof_verifier(token, ctx, proof):
                return _deny("invalid_proof")
        else:
            if not _default_pop_check(token, proof):
                return _deny("invalid_proof")
        # Permission Check (with Prefix Support)
        allowed_by_permission = False
        for p_action, p_resource in token.permissions:
            if p_action == ctx.action:
                if p_resource == ctx.resource:
                    allowed_by_permission = True
                    break
                # Hierarchical check: if permission is for /data/ and resource is /data/photos
                if p_resource.endswith("/") and ctx.resource.startswith(p_resource):
                    allowed_by_permission = True
                    break
                # Root wildcard
                if p_resource == "/":
                    allowed_by_permission = True
                    break

        if not allowed_by_permission:
            return _deny("permission_missing")
        for caveat in token.caveats:
            try:
                if not caveat.evaluate(ctx):
                    return _deny("caveat_failed")
            except Exception:
                return _deny("caveat_error")
        return ALLOW
    except Exception as exc:
        _ = exc
        return _deny("error")
