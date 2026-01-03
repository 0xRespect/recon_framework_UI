import abc
from typing import List, Optional, Any

class IRepository(abc.ABC):
    """
    Interface for Data Persistence.
    Decouples the application from the specific database implementation (SQLite/Postgres).
    """

    @abc.abstractmethod
    async def add_subdomain(self, target_domain: str, subdomain: str, source_tool: str) -> bool:
        """Adds a new subdomain. Returns True if new, False if duplicate."""
        pass

    @abc.abstractmethod
    async def get_subdomains(self, target_domain: str) -> List[str]:
        """Returns all subdomains for a target."""
        pass

    @abc.abstractmethod
    async def get_alive_subdomains(self, target_domain: str) -> List[str]:
        """Returns only alive subdomains."""
        pass

    @abc.abstractmethod
    async def update_subdomain_alive(self, subdomain: str, is_alive: bool) -> bool:
        """Updates alive status."""
        pass

    @abc.abstractmethod
    async def add_crawled_url(self, target_domain: str, url: str, source: str, tags: str = None) -> bool:
        """Adds a crawled URL."""
        pass
    
    @abc.abstractmethod
    async def get_crawled_urls(self, target_domain: str) -> List[str]:
        pass

    @abc.abstractmethod
    async def add_vulnerability(self, target_domain: str, name: str, severity: str, url: str, matcher: str = None, description: str = None) -> bool:
        """Adds a vulnerability."""
        pass
