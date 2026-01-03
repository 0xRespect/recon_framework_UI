
import pkgutil
import importlib
import inspect
from typing import Dict, Type, List
from core.providers.base import BaseProvider

class ProviderRegistry:
    def __init__(self):
        self._providers: Dict[str, Type[BaseProvider]] = {}
    
    def register(self, name: str, provider_cls: Type[BaseProvider]):
        """Registers a provider class under a normalized name."""
        self._providers[name.lower()] = provider_cls
        print(f"[Registry] Registered provider: {name}")

    def get_provider(self, name: str) -> BaseProvider:
        """Instantiates and returns a provider by name."""
        provider_cls = self._providers.get(name.lower())
        if not provider_cls:
            raise ValueError(f"Provider '{name}' not found in registry.")
        return provider_cls()

    def list_providers(self) -> List[str]:
        return list(self._providers.keys())

    def auto_discover(self, package_path: str = "core.providers"):
        """Scans the package path for classes inheriting from BaseProvider."""
        try:
            package = importlib.import_module(package_path)
            prefix = package.__name__ + "."
            
            for _, name, ispkg in pkgutil.iter_modules(package.__path__, prefix):
                module = importlib.import_module(name)
                
                for item_name, item in inspect.getmembers(module, inspect.isclass):
                    if issubclass(item, BaseProvider) and item is not BaseProvider:
                        # Use the class name or a defined 'name' attribute
                        # Convention: "SubfinderProvider" -> "subfinder" or explicit NAME attr
                        provider_name = getattr(item, 'NAME', item.__name__.replace("Provider", "")).lower()
                        self.register(provider_name, item)
        except Exception as e:
            print(f"[Registry] Discovery failed: {e}")

# Global Registry Instance
registry = ProviderRegistry()
