import unittest
import json
from proxion_core.federation import FederationInvite, InviteAcceptance, RelationshipCertificate, Capability

class MockKey:
    def sign(self, data):
        return b"mock_signature"

def mock_verifier(pubkey, sig, data):
    return sig == b"mock_signature"

class TestFederation(unittest.TestCase):
    def test_invite_creation(self):
        key = MockKey()
        cap = Capability(with_="stash://alice/files", can="read", caveats={"quota": 100})
        invite = FederationInvite(
            issuer={"public_key": "alice_pub", "did": "did:key:alice"},
            endpoint_hints=["udp://1.2.3.4"],
            capabilities=[cap]
        )
        invite.sign(key)
        
        self.assertIsNotNone(invite.signature)
        self.assertEqual(invite.issuer["public_key"], "alice_pub")
        print("Invite JSON:", json.dumps(invite.to_dict(), indent=2))
        
        # Verify
        self.assertTrue(invite.verify(mock_verifier))

    def test_acceptance(self):
        key = MockKey()
        acc = InviteAcceptance(
            invitation_id="123",
            responder={"public_key": "bob_pub"},
            challenge_response="signed_marker"
        )
        acc.sign(key)
        self.assertEqual(acc.signature, "6d6f636b5f7369676e6174757265") # hex for mock_signature

    def test_relationship(self):
        cert = RelationshipCertificate(
            issuer="alice",
            subject="bob",
            capabilities=[],
            wireguard={"ip": "10.99.0.2"}
        )
        cert.sign(MockKey())
        self.assertTrue(cert.signature)

if __name__ == "__main__":
    unittest.main()
