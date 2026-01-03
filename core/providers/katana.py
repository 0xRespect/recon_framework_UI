import asyncio
import shlex
import json
from typing import List, Dict, Any, AsyncGenerator
from .base import BaseProvider

class KatanaProvider(BaseProvider):
    def __init__(self):
        super().__init__("Katana")

    async def run(self, target: str, config: Dict[str, Any], scan_id: str = None) -> List[Dict[str, Any]]:
        results = []
        async for item in self.stream_output(target, config, scan_id):
            if item["type"] == "result":
                results.append(item["data"])
        return results

    async def stream_output(self, target: str, config: Dict[str, Any], scan_id: str = None) -> AsyncGenerator[Dict[str, Any], None]:
        # katana -u target -j -jc ...
        
        default_flags = ["-j", "-jc", "-silent", "-d", "3"]
        extra_flags = await self.get_config("tool:katana:flags", default_flags)
        
        cmd_list = ["stdbuf", "-oL", "katana", "-u", target] + extra_flags
        command = shlex.join(cmd_list)
        
        yield {"type": "log", "data": f"[*] Starting Katana on {target}..."}
        
        try:
            process = await self._run_command(command, scan_id)
            
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                decoded = line.decode('utf-8').strip()
                if decoded:
                    try:
                        data = json.loads(decoded)
                        # Katana JSON structure: endpoint, source, etc.
                        yield {"type": "result", "data": data}
                        
                        endpoint = data.get("request", {}).get("endpoint")
                        if not endpoint:
                             # Try fallback or debug
                             endpoint = data.get("url", "N/A")
                        
                        yield {"type": "log", "data": f"[Katana] Found: {endpoint}"}
                    except json.JSONDecodeError:
                        yield {"type": "log", "data": f"[Katana] (Raw) {decoded}"}

            await process.wait()
            yield {"type": "log", "data": "[*] Katana Complete."}

        except asyncio.CancelledError:
            yield {"type": "error", "data": "Katana cancelled."}
            raise
        except Exception as e:
            yield {"type": "error", "data": f"Katana Failed: {e}"}
