import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from proxion_core.attenuation import derive_token
from proxion_core.context import Caveat
from proxion_core.errors import AttenuationError
from proxion_core.tokens import issue_token


class AttenuationTests(unittest.TestCase):
    def test_widening_raises(self) -> None:
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
        with self.assertRaises(AttenuationError):
            derive_token(
                parent=token,
                narrower_perms={("read", "resource"), ("write", "resource")},
                extra_caveats=[Caveat("extra", lambda ctx: True)],
                now=now,
                signing_key=signing_key,
            )


if __name__ == "__main__":
    unittest.main()
