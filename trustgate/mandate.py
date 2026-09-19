import json
import time

from trustgate.crypto import sign, verify


def create_mandate(max_amount_cents: int, allowed_merchants: list[str], expires_at: float) -> dict:
    """Return a dict with the agent's limits.
    Keys: "max_amount_cents", "allowed_merchants", "expires_at"."""

    return {'max_amount_cents': max_amount_cents, 'allowed_merchants': allowed_merchants, 'expires_at': expires_at}


def mandate_bytes(mandate: dict) -> bytes:
    """Return the mandate as canonical bytes: the same mandate must give the same bytes every time."""

    m =json.dumps(mandate, sort_keys=True)
    return m.encode()


def sign_mandate(human_private_key, mandate: dict) -> bytes:
    """Return the human's signature over the mandate."""

    bytes_mandate = mandate_bytes(mandate)
    return sign(human_private_key, bytes_mandate)


def verify_mandate(human_public_key, mandate: dict, signature: bytes) -> bool:
    """Return True if the human signed exactly this mandate, else False."""
    return verify(human_public_key, mandate_bytes(mandate),signature)


def purchase_allowed(mandate: dict, amount_cents: int, merchant: str, now: float | None = None) -> bool:
    """Return True only if ALL of these hold:
    - amount_cents <= the mandate's max
    - merchant is in the allowed list
    - now is before expires_at
    Otherwise return False."""
    if now is None:
        now = time.time()
    under_cap = amount_cents <= mandate['max_amount_cents']
    merchant_check = merchant in mandate['allowed_merchants']
    not_expired = now < mandate['expires_at']

    return under_cap and merchant_check and not_expired


    


