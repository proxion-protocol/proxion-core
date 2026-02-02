import os
import sys
import unittest
from datetime import datetime, timezone, timedelta
from dataclasses import replace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from proxion_core.context import Caveat, RequestContext
from proxion_core.tokens import issue_token
from proxion_core.validator import validate_request


class TokenTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signing_key = b"test-key"
        self.now = datetime.now(timezone.utc)
        self.exp = self.now + timedelta(minutes=5)
        self.perms = {("read", "resource")}
        self.caveat = Caveat("allow_local", lambda ctx: ctx.ip == "127.0.0.1")
        self.token = issue_token(
            permissions=self.perms,
            exp=self.exp,
            aud="aud1",
            caveats=[self.caveat],
            holder_key_fingerprint="fp1",
            signing_key=self.signing_key,
            now=self.now,
        )

    def test_token_expired_denies(self) -> None:
        ctx = RequestContext("read", "resource", "aud1", self.exp + timedelta(seconds=1))
        decision = validate_request(self.token, ctx, {"holder_key_fingerprint": "fp1"}, self.signing_key)
        self.assertFalse(decision.allowed)

    def test_permission_missing_denies(self) -> None:
        ctx = RequestContext("write", "resource", "aud1", self.now, ip="127.0.0.1")
        decision = validate_request(self.token, ctx, {"holder_key_fingerprint": "fp1"}, self.signing_key)
        self.assertFalse(decision.allowed)

    def test_caveat_fails_denies(self) -> None:
        ctx = RequestContext("read", "resource", "aud1", self.now, ip="10.0.0.1")
        decision = validate_request(self.token, ctx, {"holder_key_fingerprint": "fp1"}, self.signing_key)
        self.assertFalse(decision.allowed)

    def test_audience_mismatch_denies(self) -> None:
        ctx = RequestContext("read", "resource", "aud2", self.now, ip="127.0.0.1")
        decision = validate_request(self.token, ctx, {"holder_key_fingerprint": "fp1"}, self.signing_key)
        self.assertFalse(decision.allowed)

    def test_missing_or_invalid_proof_denies(self) -> None:
        ctx = RequestContext("read", "resource", "aud1", self.now, ip="127.0.0.1")
        missing = validate_request(self.token, ctx, None, self.signing_key)
        invalid = validate_request(self.token, ctx, {"holder_key_fingerprint": "wrong"}, self.signing_key)
        self.assertFalse(missing.allowed)
        self.assertFalse(invalid.allowed)

    def test_malformed_token_denies(self) -> None:
        ctx = RequestContext("read", "resource", "aud1", self.now, ip="127.0.0.1")
        bad = replace(self.token, signature="bad")
        decision = validate_request(bad, ctx, {"holder_key_fingerprint": "fp1"}, self.signing_key)
        self.assertFalse(decision.allowed)


if __name__ == "__main__":
    unittest.main()
