from trustgate.crypto import generate_keypair, sign, verify


def test_valid_signature_verifies():
    """A signature made with a private key should verify with its matching public key.
    Expected: verify(...) returns True."""

    private_key,public_key = generate_keypair()
    message = b"Buy item X for $40"
    signature = sign(private_key, message)
    assert verify(public_key, message,signature) is True
    


def test_tampered_message_fails():
    """If the message changes after signing, verification should fail.
    Expected: verify(...) returns False."""

    private_key , public_key = generate_keypair()
    message = b"Buy Item X for $85"
    signature = sign(private_key, message)
    assert verify(public_key, b"Buy Item X for $10000", signature) is False


def test_wrong_key_fails():
    """A signature should only verify with the public key that matches the signer's private key.
    Expected: verify(...) returns False."""

    private_key , public_key = generate_keypair()
    _ , other_public_key = generate_keypair()
    message = b"Buy item X for $45"
    signature = sign(private_key, message)
    assert verify(other_public_key, message, signature) is False

