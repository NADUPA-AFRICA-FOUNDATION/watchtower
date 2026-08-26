"""Discovery providers.

Every provider returns :class:`ProviderResult`; an unavailable or failed lane
is never represented by an empty list.
"""

from discovery.providers.base import ProviderResult, ProviderState

__all__ = ["ProviderResult", "ProviderState"]
