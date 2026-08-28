"""Shared records used by discovery providers and their callers."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Candidate:
    """An unverified lead returned by a discovery provider."""

    url: str
    source_url: str = ""
    source: str = ""
    source_kind: str = ""
    title: str = ""
    text: str = ""
    author: str = ""
    published_at: Optional[datetime] = None
    query: str = ""
    promotion_context: str = ""
    raw_meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderResult:
    """Outcome of one provider invocation.

    ``candidates=[]`` is meaningful only when ``searched`` is true.  Failures
    and skips therefore remain explicit results instead of being collapsed to
    ordinary empty lists.
    """

    provider: str
    candidates: List[Candidate] = field(default_factory=list)
    searched: bool = False
    failed: bool = False
    skipped: bool = False
    result_count: int = 0
    error: Optional[str] = None

    def __post_init__(self) -> None:
        states = sum(bool(value) for value in
                     (self.searched, self.failed, self.skipped))
        if states != 1:
            raise ValueError("exactly one of searched, failed, or skipped must be true")
        if self.searched:
            self.result_count = len(self.candidates)
        elif self.candidates or self.result_count:
            raise ValueError("failed or skipped providers cannot report results")

    @classmethod
    def success(cls, provider: str, candidates: List[Candidate]) -> "ProviderResult":
        return cls(provider=provider, candidates=list(candidates), searched=True)

    @classmethod
    def failure(cls, provider: str, error: str) -> "ProviderResult":
        return cls(provider=provider, failed=True, error=error)

    @classmethod
    def skip(cls, provider: str, reason: str = "disabled") -> "ProviderResult":
        return cls(provider=provider, skipped=True, error=reason)
