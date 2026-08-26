"""Interface implemented by candidate discovery providers."""

from abc import ABC, abstractmethod
from typing import Any, Callable, Mapping, Sequence, Union

from .models import ProviderResult

Progress = Callable[[Mapping[str, Any]], None]
QueryPlan = Union[Sequence[str], Mapping[str, Any]]


class DiscoveryProvider(ABC):
    """A source which searches for unverified Watchtower candidates."""

    name: str
    enabled: bool = True

    @abstractmethod
    def search(self, brand_profile: Mapping[str, Any], query_plan: QueryPlan,
               progress: Progress) -> ProviderResult:
        """Run this provider, returning an explicit outcome in all cases."""
