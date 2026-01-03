import abc
import asyncio
from typing import List, Dict, Any, AsyncGenerator

class BaseProvider(abc.ABC):
    """
    Abstract Base Class for all Tool Providers.
    Enforces a standard interface for execution, configuration, and output streaming.
    """

    def __init__(self, name: str):
        self.name = name

    @abc.abstractmethod
    async def run(self, target: str, config: Dict[str, Any], scan_id: str = None) -> List[Any]:
        """
        Executes the tool and returns the final results.
        Should handle its own process management and parsing.
        """
        pass

    @abc.abstractmethod
    async def stream_output(self, target: str, config: Dict[str, Any], scan_id: str = None) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Async generator that yields real-time results/logs.
        
        Yields:
            Dict: {"type": "log|result", "data": ...}
        """
        pass
    
    async def _run_command(self, command: str, scan_id: str = None) -> asyncio.subprocess.Process:
        """Helper to run a shell command properly."""
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        return process
