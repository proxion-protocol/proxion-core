import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from proxion_core.caveats import ip_allowlist, time_window, nonce_matches
from proxion_core.context import RequestContext
from proxion_core.tokens import issue_token
from proxion_core.validator import validate_request


class CaveatTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signing_key = b"test-key"
        self.now = datetime.now(timezone.utc)
        self.exp = self.now + timedelta(minutes=5)

    def _issue(self, caveat):
        return issue_token(
            permissions={("read", "resource")},
            exp=self.exp,
            aud="aud1",
            caveats=[caveat],
            holder_key_fingerprint="fp1",
            signing_key=self.signing_key,
            now=self.now,
        )

    def test_ip_allowlist_allows_and_denies(self) -> None:
        token = self._issue(ip_allowlist({"127.0.0.1"}))
        ok_ctx = RequestContext("read", "resource", "aud1", self.now, ip="127.0.0.1")
        bad_ctx = RequestContext("read", "resource", "aud1", self.now, ip="10.0.0.1")
        ok = validate_request(token, ok_ctx, {"holder_key_fingerprint": "fp1"}, self.signing_key)
        bad = validate_request(token, bad_ctx, {"holder_key_fingerprint": "fp1"}, self.signing_key)
        self.assertTrue(ok.allowed)
        self.assertFalse(bad.allowed)

    def test_time_window_denies_outside(self) -> None:
        caveat = time_window(self.now.timestamp() - 5, self.now.timestamp() + 5)
        token = self._issue(caveat)
        outside = RequestContext("read", "resource", "aud1", self.now + timedelta(seconds=10))
        decision = validate_request(token, outside, {"holder_key_fingerprint": "fp1"}, self.signing_key)
        self.assertFalse(decision.allowed)

    def test_nonce_matches_denies_on_mismatch(self) -> None:
        token = self._issue(nonce_matches("nonce-123"))
        ctx = RequestContext("read", "resource", "aud1", self.now, device_nonce="nonce-999")
        decision = validate_request(token, ctx, {"holder_key_fingerprint": "fp1"}, self.signing_key)
        self.assertFalse(decision.allowed)

    def test_caveat_false_denies(self) -> None:
        token = self._issue(ip_allowlist(set()))
        ctx = RequestContext("read", "resource", "aud1", self.now, ip="127.0.0.1")
        decision = validate_request(token, ctx, {"holder_key_fingerprint": "fp1"}, self.signing_key)
        self.assertFalse(decision.allowed)


if __name__ == "__main__":
    unittest.main()
