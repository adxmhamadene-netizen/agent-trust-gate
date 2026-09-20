import json
import time
from pathlib import Path


class AuditLog:
    """Append-only record of decisions, one JSON object per line (JSONL)."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        

    def append(self, event: str, **fields) -> dict:
        """Write one entry and return it."""
        entry = {"ts": int(time.time()), "event": event, **fields}
        with self.path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        return entry
        

    def read_all(self) -> list[dict]:
        """Return every entry, oldest first."""
        if not self.path.exists():
            return []
        with self.path.open() as f:
            return [json.loads(line) for line in f if line.strip()]
        
        