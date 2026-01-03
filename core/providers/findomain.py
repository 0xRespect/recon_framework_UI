import asyncio
import shlex
from typing import List, Dict, Any, AsyncGenerator
from .base import BaseProvider

class FindomainProvider(BaseProvider):
    def __init__(self):
        super().__init__("Findomain")

    async def run(self, target: str, config: Dict[str, Any], scan_id: str = None) -> List[str]:
        results = []
        async for item in self.stream_output(target, config, scan_id):
            if item["type"] == "result":
                results.append(item["data"])
        return results

    async def stream_output(self, target: str, config: Dict[str, Any], scan_id: str = None) -> AsyncGenerator[Dict[str, Any], None]:
        cmd_list = ["findomain", "-t", target, "-q"]
        command = shlex.join(cmd_list)
        
        yield {"type": "log", "data": f"[*] Starting Findomain for {target}..."}
        
        try:
            process = await self._run_command(command, scan_id)
            
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                decoded = line.decode('utf-8').strip()
                if decoded:
                    # Findomain usually outputs just the domain with -q
                    if target in decoded:
                         yield {"type": "result", "data": decoded}
                         yield {"type": "log", "data": f"[Findomain] Found: {decoded}"}


            await process.wait()
            yield {"type": "log", "data": "[*] Findomain Complete."}

        except asyncio.CancelledError:
             yield {"type": "error", "data": "Findomain cancelled."}
             raise
        except Exception as e:
             yield {"type": "error", "data": f"Findomain Failed: {e}"}
