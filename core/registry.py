from typing import Dict, Type, List
from core.providers.base import BaseProvider
from core.providers.subfinder import SubfinderProvider
from core.providers.assetfinder import AssetfinderProvider
from core.providers.findomain import FindomainProvider
from core.providers.httpx import HTTPXProvider
from core.providers.katana import KatanaProvider
from core.providers.nuclei import NucleiProvider

class ProviderRegistry:
    """
    Central registry to manage and execute tool providers.
    """
    def __init__(self):
        self._providers: Dict[str, BaseProvider] = {}
        self._register_defaults()

    def _register_defaults(self):
        self.register_provider(SubfinderProvider())
        self.register_provider(AssetfinderProvider())
        self.register_provider(FindomainProvider())
        self.register_provider(HTTPXProvider())
        self.register_provider(KatanaProvider())
        self.register_provider(NucleiProvider())

    def register_provider(self, provider: BaseProvider):
        """Register a new provider instance."""
        self._providers[provider.name.lower()] = provider

    def get_provider(self, name: str) -> BaseProvider:
        """Get a provider by name."""
        return self._providers.get(name.lower())

    def list_providers(self) -> List[str]:
        return list(self._providers.keys())

# Singleton instance
registry = ProviderRegistry()
