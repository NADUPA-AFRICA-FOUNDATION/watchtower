from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProviderState(str, Enum):
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class ProviderResult:
    provider: str
    state: ProviderState
    candidates: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    credential_requirement: str = "none"

    def __post_init__(self) -> None:
        if self.state is not ProviderState.SUCCESS and not self.reason:
            raise ValueError("a skipped or failed provider must include a reason")


def credential(config: dict, provider: str, env_name: str) -> str:
    """Read a provider credential from config first and then the environment."""
    import os
    value = config.get("discovery", {}).get("providers", {}).get(provider, {}).get("api_key")
    return str(value or os.getenv(env_name, ""))
