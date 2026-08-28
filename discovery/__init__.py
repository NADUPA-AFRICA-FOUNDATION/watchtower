"""Provider-based candidate discovery.

The package deliberately models provider failure separately from a successful
search which happened to return no candidates.  Consumers should inspect the
per-provider results returned by :class:`DiscoveryEngine`, rather than treating
an empty candidate list as proof that every source was searched.
"""

from .engine import DiscoveryEngine, DiscoveryRun
from .models import Candidate, ProviderResult
from .provider import DiscoveryProvider

__all__ = [
    "Candidate",
    "DiscoveryEngine",
    "DiscoveryProvider",
    "DiscoveryRun",
    "ProviderResult",
]
