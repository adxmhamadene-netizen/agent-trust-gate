from trustgate.crypto import generate_keypair
from trustgate.mandate import create_mandate, sign_mandate, verify_mandate, purchase_allowed


def test_signed_mandate_verifies():
    """A mandate signed by the human should verify with the human's public key.
    Expected: verify_mandate(...) is True."""

    private_key , public_key = generate_keypair()
    mandate = create_mandate(5000, ["Nike", "Adidas"], expires_at=1000)
    signature = sign_mandate(private_key, mandate)
    assert verify_mandate(public_key, mandate, signature) is True


def test_edited_mandate_fails():
    """If anyone changes the mandate after signing (e.g. raises the cap), verification should fail.
    Expected: verify_mandate(...) is False."""

    private_key, public_key = generate_keypair()
    mandate = create_mandate(5000, ["Nike", "Adidas"], expires_at=1000)
    signature = sign_mandate(private_key, mandate)
    mandate["max_amount_cents"] = 500000
    assert verify_mandate(public_key, mandate, signature) is False

def test_purchase_within_limits_allowed():
    """Under the cap, allowed merchant, before expiry → allowed.
    Expected: purchase_allowed(...) is True."""

    mandate = create_mandate(5000, ["Nike", "Adidas"], expires_at=1000)
    assert purchase_allowed(mandate, 3000, "Nike", now=999) is True


def test_over_cap_blocked():
    """Amount above the cap → blocked.
    Expected: purchase_allowed(...) is False."""

    mandate = create_mandate(5000, ["Nike", "Adidas"], expires_at=1000)
    assert purchase_allowed(mandate, 9000, "Nike", now=999) is False



def test_wrong_merchant_blocked():
    """Merchant not in the allowed list → blocked.
    Expected: purchase_allowed(...) is False."""

    mandate = create_mandate(5000, ["Nike", "Adidas"], expires_at=1000)
    assert purchase_allowed(mandate, 3000, "Puma", now=999) is False


def test_expired_mandate_blocked():
    """Purchase after the expiry time → blocked.
    Expected: purchase_allowed(...) is False."""

    mandate = create_mandate(5000, ["Nike", "Adidas"], expires_at=1000)
    assert purchase_allowed(mandate, 3000, "Nike", now=1001) is False
    