import json
import secrets
import time

from trustgate.crypto import sign, verify

MAX_AGE_SECONDS = 300  


def create_request(amount_cents: int, merchant: str, now: float | None = None) -> dict:
    """Return a purchase request dict.
    Keys: "amount_cents", "merchant", "nonce", "timestamp".
    - nonce: a random ID, different for every request
    - timestamp: when the request was made (now)"""

    if now is None:
        now = time.time()
    nonce = secrets.token_hex(16)

    return {'amount_cents':amount_cents, 'merchant': merchant, 'nonce': nonce, 'timestamp':now}


def request_bytes(request: dict) -> bytes:
    """Return the request as canonical bytes (same idea as mandate_bytes)."""

    r = json.dumps(request, sort_keys = True)
    return r.encode()


def sign_request(agent_private_key, request: dict) -> bytes:
    """Return the agent's signature over the request."""

    bytes_request = request_bytes(request)
    return sign(agent_private_key, bytes_request)


class NonceStore:
    """Remembers every nonce the gate has already accepted."""

    def __init__(self):
        """Start with an empty set of seen nonces."""
        self.seen = set()

    def check_and_add(self, nonce: str) -> bool:
        """Return True if the nonce is new (and remember it).
        Return False if it was seen before (a replay)."""

        if nonce in self.seen:
            return False
        else:
            self.seen.add(nonce)
            return True


def request_valid(agent_public_key, request: dict, signature: bytes,
                  nonce_store: NonceStore, now: float | None = None) -> bool:
    """Return True only if ALL of these hold:
    - the signature is valid for this request
    - the request is fresh: now - timestamp <= MAX_AGE_SECONDS
    - the nonce is new (check this LAST)
    Otherwise return False."""

    if now is None:
        now = time.time()

    sig_valid = verify(agent_public_key, request_bytes(request), signature)
    if not sig_valid:
        return False

    request_time = now - request['timestamp'] <= MAX_AGE_SECONDS
    if not request_time:
        return False

    return nonce_store.check_and_add(request['nonce'])


    