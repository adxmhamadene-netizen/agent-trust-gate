from trustgate.crypto import generate_keypair
from trustgate.request import create_request, sign_request, request_valid, NonceStore


def test_valid_request_accepted():
    """A fresh, correctly signed request with a new nonce is accepted.
    Expected: request_valid(...) is True."""

    private_key, public_key = generate_keypair()
    store = NonceStore()
    request = create_request(3000, "Nike")
    signature = sign_request(private_key, request)
    assert request_valid(public_key, request, signature, store) is True


def test_replay_blocked():
    """Sending the exact same signed request twice: first accepted, second blocked.
    Expected: first is True, second is False."""

    private_key, public_key = generate_keypair()
    store = NonceStore()
    request = create_request(3000, "Nike")
    signature = sign_request(private_key, request)
    assert request_valid(public_key, request, signature, store) is True
    assert request_valid(public_key, request, signature, store) is False

    


def test_stale_request_blocked():
    """A request older than MAX_AGE_SECONDS (300) is rejected.
    Expected: request_valid(...) is False."""

    private_key, public_key = generate_keypair()
    store = NonceStore()
    request = create_request(3000, "Nike", now=1000)
    signature = sign_request(private_key, request)
    assert request_valid(public_key, request, signature, store, now=1301) is False

    


def test_tampered_request_fails():
    """Changing the request after signing (e.g. the amount) breaks the signature.
    Expected: request_valid(...) is False."""

    private_key, public_key = generate_keypair()
    store = NonceStore()
    request = create_request(3000, "Nike")
    signature = sign_request(private_key, request)
    request["amount_cents"] = 900000
    assert request_valid(public_key, request, signature, store) is False



def test_nonces_are_unique():
    """Two requests should never share a nonce.
    Expected: the two nonces are different."""

    request_one = create_request(3000, "Nike")
    request_two = create_request(3000, "Nike")
    assert request_one['nonce'] != request_two['nonce']