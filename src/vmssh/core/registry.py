from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from vmssh.core.models import VMConfig
from vmssh.utils.backup import atomic_write


class VMRegistry:
    """Local metadata only. Passwords and private-key contents are never stored."""
    def __init__(self, path: Path | None = None):
        if path is None:
            base = Path(os.environ.get("APPDATA", str(Path.home() / ".config"))) / "VM SSH Manager"
            path = base / "vms.json"
        self.path = Path(path)

    def all(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def upsert(self, config: VMConfig, sudo_enabled: bool, status: str = "configured") -> None:
        records = self.all()
        record = {
            "host_alias": config.host_alias,
            "hostname": config.hostname,
            "username": config.username,
            "port": config.port,
            "key_path": str(config.key_path) if config.key_path else "",
            "notes": config.notes,
            "sudo_nopasswd": bool(sudo_enabled),
            "status": status if status in {"configured", "partial"} else "partial",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        records = [r for r in records if r.get("host_alias") != config.host_alias]
        records.append(record)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.path, json.dumps(records, ensure_ascii=False, indent=2) + "\n")

    def remove(self, alias: str) -> None:
        records = [r for r in self.all() if r.get("host_alias") != alias]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.path, json.dumps(records, ensure_ascii=False, indent=2) + "\n")
