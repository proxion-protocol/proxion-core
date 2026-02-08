import json
import jwt
from datetime import datetime, timezone
import base64

class TokenSerializer:
    """Standard JWT-based serializer for Proxion Capability Tokens."""

    def __init__(self, issuer: str):
        self.issuer = issuer

    def sign(self, token, signing_key) -> str:
        """Sign a Token object into a JWT string."""
        payload = token.payload()
        # Add standard JWT claims
        payload.update({
            "iss": self.issuer,
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "jti": token.token_id
        })
        
        # We use EdDSA as standard for Proxion
        headers = {"kid": token.token_id[:16]} # Optional: use token_id as kid
        return jwt.encode(payload, signing_key, algorithm="EdDSA", headers=headers)

    def verify(self, token_str: str, public_key) -> dict:
        """Verify a Proxion JWT and return the payload."""
        return jwt.decode(token_str, public_key, algorithms=["EdDSA"], options={"verify_aud": False})
