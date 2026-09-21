from trustgate.crypto import sign, verify
from trustgate.request import request_bytes


class Approver:
    """Interface: show a request to a human, return their signature or None."""

    def approve(self, request: dict) -> bytes | None:
        raise NotImplementedError


class AutoApprover(Approver):
    """Test double. Always approves (or always declines) without asking."""

    def __init__(self, human_private_key, decision=True):
        self.human_private_key = human_private_key
        self.decision = decision

    def approve(self, request):
        if not self.decision:
            return None
        return sign(self.human_private_key, request_bytes(request))


class CLIApprover(Approver):
    """Prints the request, waits for y/n at the terminal."""

    def __init__(self, human_private_key):
        self.human_private_key = human_private_key

    def approve(self, request):
        print(f"\nApproval needed: {request['amount_cents']} cents "
              f"at {request['merchant']}")
        answer = input("Approve? [y/N] ").strip().lower()
        if answer != "y":
            return None
        return sign(self.human_private_key, request_bytes(request))


def approval_valid(human_public_key, request: dict, signature: bytes) -> bool:
    """True if the human signed exactly this request."""
    return verify(human_public_key, request_bytes(request), signature)