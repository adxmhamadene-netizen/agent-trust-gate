# agent-trust-gate

> Agents should be accountable, not just capable: the model proposes, deterministic code decides, and a human approves anything high-stakes.

A shopping agent that runs on its own but can't spend beyond what it's been trusted with. Signed ≠ trusted: signatures prove who's asking; a deterministic trust gate decides whether it goes through.

## Roadmap
- [ ] PR 1: Ed25519 sign/verify
- [ ] PR 2: Signed mandates
- [ ] PR 3: Replay protection
- [ ] PR 4: Risk provider interface + local scorer
- [ ] PR 5: Audit log
- [ ] PR 6: Agent loop
- [ ] PR 7: Human-in-the-loop approval
- [ ] PR 8: Attack suite
- [ ] PR 9: Architecture + writeup
