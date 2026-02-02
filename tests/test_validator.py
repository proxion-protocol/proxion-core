import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from proxion_core.context import RequestContext
from proxion_core.revocation import RevocationList
from proxion_core.tokens import issue_token
from proxion_core.validator import validate_request


class ValidatorTests(unittest.TestCase):
    def test_valid_token_allows(self) -> None:
        signing_key = b"test-key"
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=5)
        token = issue_token(
            permissions={("read", "resource")},
            exp=exp,
            aud="aud1",
            caveats=[],
            holder_key_fingerprint="fp1",
            signing_key=signing_key,
            now=now,
        )
        ctx = RequestContext("read", "resource", "aud1", now)
        decision = validate_request(
            token,
            ctx,
            {"holder_key_fingerprint": "fp1"},
            signing_key,
        )
        self.assertTrue(decision.allowed)

    def test_revoked_token_denies(self) -> None:
        signing_key = b"test-key"
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=5)
        token = issue_token(
            permissions={("read", "resource")},
            exp=exp,
            aud="aud1",
            caveats=[],
            holder_key_fingerprint="fp1",
            signing_key=signing_key,
            now=now,
        )
        ctx = RequestContext("read", "resource", "aud1", now)
        revocations = RevocationList()
        revocations.revoke(token, now)
        decision = validate_request(
            token,
            ctx,
            {"holder_key_fingerprint": "fp1"},
            signing_key,
            revocation_list=revocations,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("revoked", decision.reason or "")

    def test_revocation_ttl_expires_allows(self) -> None:
        signing_key = b"test-key"
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=5)
        token = issue_token(
            permissions={("read", "resource")},
            exp=exp,
            aud="aud1",
            caveats=[],
            holder_key_fingerprint="fp1",
            signing_key=signing_key,
            now=now,
        )
        ctx = RequestContext("read", "resource", "aud1", now)
        revocations = RevocationList()
        revocations.revoke(token, now, ttl_seconds=1)
        later = now + timedelta(seconds=2)
        decision = validate_request(
            token,
            RequestContext("read", "resource", "aud1", later),
            {"holder_key_fingerprint": "fp1"},
            signing_key,
            revocation_list=revocations,
        )
        self.assertTrue(decision.allowed)

    def test_purge_removes_expired_entries(self) -> None:
        signing_key = b"test-key"
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=5)
        token = issue_token(
            permissions={("read", "resource")},
            exp=exp,
            aud="aud1",
            caveats=[],
            holder_key_fingerprint="fp1",
            signing_key=signing_key,
            now=now,
        )
        revocations = RevocationList()
        revocations.revoke(token, now, ttl_seconds=1)
        removed = revocations.purge(now + timedelta(seconds=2))
        self.assertEqual(removed, 1)

    def test_revocation_derivation_error_denies(self) -> None:
        signing_key = b"test-key"
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=5)
        token = issue_token(
            permissions={("read", "resource")},
            exp=exp,
            aud="aud1",
            caveats=[],
            holder_key_fingerprint="fp1",
            signing_key=signing_key,
            now=now,
        )
        ctx = RequestContext("read", "resource", "aud1", now)
        revocations = RevocationList()

        class MalformedToken:
            pass

        decision = validate_request(
            MalformedToken(),  # type: ignore[arg-type]
            ctx,
            {"holder_key_fingerprint": "fp1"},
            signing_key,
            revocation_list=revocations,
        )
        self.assertFalse(decision.allowed)


if __name__ == "__main__":
    unittest.main()
