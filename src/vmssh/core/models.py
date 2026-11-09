from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class VMConfig:
    hostname: str
    username: str
    host_alias: str
    port: int = 22
    key_path: Path | None = None
    notes: str = ""


@dataclass(slots=True)
class StepResult:
    name: str
    status: str
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class InitReport:
    config: VMConfig
    steps: list[StepResult] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None

    @property
    def success(self) -> bool:
        """True when every enabled operation completed successfully.

        Deliberately skipped optional actions are not failures. Any failed or
        cancelled action remains a failed initialization report.
        """
        statuses = {step.name: step.status for step in self.steps}
        required = {"key_validation", "ssh_password_connection"}
        for name in ("public_key_deployment", "ssh_config", "public_key_authentication"):
            if statuses.get(name) != "skipped":
                required.add(name)
        return all(statuses.get(name) == "success" for name in required) and all(
            step.status not in {"failed", "cancelled"} for step in self.steps
        )

    def finish(self) -> None:
        self.finished_at = datetime.now(timezone.utc).isoformat()
