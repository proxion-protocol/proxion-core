import json
import uuid
import time
import secrets
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any

@dataclass
class Capability:
    """UCAN-style capability."""
    with_: str  # Resource URI (e.g. stash://alice/shared/bob)
    can: str    # Action (e.g. crud/read)
    caveats: Dict[str, Any] = field(default_factory=dict) # quota_mb, etc.

    def to_dict(self):
        return {"with": self.with_, "can": self.can, "caveats": self.caveats}

@dataclass
class FederationInvite:
    """A signed invitation to federate."""
    issuer: Dict[str, str] # {public_key, did}
    endpoint_hints: List[str]
    capabilities: List[Capability]
    
    version: int = 1
    invitation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = field(default_factory=lambda: int(time.time()) + 86400)
    nonce: str = field(default_factory=lambda: secrets.token_hex(32))
    challenge_marker: str = field(default_factory=lambda: secrets.token_hex(32))
    signature: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "invitation_id": self.invitation_id,
            "issuer": self.issuer,
            "endpoint_hints": self.endpoint_hints,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "challenge_marker": self.challenge_marker,
            "signature": self.signature
        }

    def sign(self, identity_key):
        """Sign the invite with Identity Key."""
        data = self.to_dict()
        if 'signature' in data: del data['signature']
        
        canonical = json.dumps(data, sort_keys=True)
        # Assuming identity_key has .sign() returning hex or bytes
        # For simplicity in this mock, we use a placeholder if no key provided
        if hasattr(identity_key, 'sign'):
            sig_bytes = identity_key.sign(canonical.encode())
            self.signature = sig_bytes.hex() if isinstance(sig_bytes, bytes) else str(sig_bytes)

    def verify(self, verifier_func) -> bool:
        """Verify signature using a provided verifier function (pubkey, sig, data)."""
        if not self.signature: return False
        data = self.to_dict()
        del data['signature']
        canonical = json.dumps(data, sort_keys=True)
        return verifier_func(self.issuer['public_key'], bytes.fromhex(self.signature), canonical.encode())

@dataclass
class InviteAcceptance:
    """Response to an invite, proving possession."""
    invitation_id: str
    responder: Dict[str, Any] # {public_key, endpoint_hints}
    challenge_response: str   # Signature of challenge_marker
    
    timestamp: int = field(default_factory=lambda: int(time.time()))
    signature: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "invitation_id": self.invitation_id,
            "responder": self.responder,
            "challenge_response": self.challenge_response,
            "timestamp": self.timestamp,
            "signature": self.signature
        }

    def sign(self, identity_key):
        data = self.to_dict()
        if 'signature' in data: del data['signature']
        canonical = json.dumps(data, sort_keys=True)
        if hasattr(identity_key, 'sign'):
             sig_bytes = identity_key.sign(canonical.encode())
             self.signature = sig_bytes.hex() if isinstance(sig_bytes, bytes) else str(sig_bytes)

@dataclass
class RelationshipCertificate:
    """The mutual capability token."""
    issuer: str # pubkey
    subject: str # pubkey
    capabilities: List[Capability]
    wireguard: Dict[str, Any]
    
    version: int = 1
    certificate_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = field(default_factory=lambda: int(time.time()) + (90 * 86400)) # 90 days
    signature: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "certificate_id": self.certificate_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "wireguard": self.wireguard,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "signature": self.signature
        }

    def sign(self, identity_key):
        data = self.to_dict()
        if 'signature' in data: del data['signature']
        canonical = json.dumps(data, sort_keys=True)
        if hasattr(identity_key, 'sign'):
             sig_bytes = identity_key.sign(canonical.encode())
             self.signature = sig_bytes.hex() if isinstance(sig_bytes, bytes) else str(sig_bytes)
