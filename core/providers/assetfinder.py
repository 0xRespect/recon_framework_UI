import asyncio
import shlex
from typing import List, Dict, Any, AsyncGenerator
from .base import BaseProvider

class AssetfinderProvider(BaseProvider):
    def __init__(self):
        super().__init__("Assetfinder")

    async def run(self, target: str, config: Dict[str, Any], scan_id: str = None) -> List[str]:
        results = []
        async for item in self.stream_output(target, config, scan_id):
            if item["type"] == "result":
                results.append(item["data"])
        return results

    async def stream_output(self, target: str, config: Dict[str, Any], scan_id: str = None) -> AsyncGenerator[Dict[str, Any], None]:
        cmd_list = ["assetfinder", "--subs-only", target]
        command = shlex.join(cmd_list)
        
        yield {"type": "log", "data": f"[*] Starting Assetfinder for {target}..."}
        
        try:
            process = await self._run_command(command, scan_id)
            
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                decoded = line.decode('utf-8').strip()
                if decoded:
                    # Assetfinder might output the domain itself or unrelated things? 
                    # --subs-only should be clean, but good to filter if needed.
                    if target in decoded:
                        yield {"type": "result", "data": decoded}
                        yield {"type": "log", "data": f"[Assetfinder] Found: {decoded}"}
            
            await process.wait()
            yield {"type": "log", "data": "[*] Assetfinder Complete."}

        except asyncio.CancelledError:
             yield {"type": "error", "data": "Assetfinder cancelled."}
             raise
        except Exception as e:
             yield {"type": "error", "data": f"Assetfinder Failed: {e}"}
