from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_conformance import _did_of, _signature


def test_did_and_signature_shape() -> None:
    key = Ed25519PrivateKey.generate()

    did = _did_of(key)
    sig = _signature(key, "room|1|hello")

    assert did.startswith("did:key:z6Mk")
    assert len(did) == 56
    assert len(sig) == 86
    assert "=" not in sig
