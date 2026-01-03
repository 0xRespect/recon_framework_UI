import asyncio
import shlex
import json
from typing import List, Dict, Any, AsyncGenerator
from .base import BaseProvider

class NucleiProvider(BaseProvider):
    def __init__(self):
        super().__init__("Nuclei")

    async def run(self, target: str, config: Dict[str, Any], scan_id: str = None) -> List[Dict[str, Any]]:
        results = []
        async for item in self.stream_output(target, config, scan_id):
            if item["type"] == "result":
                results.append(item["data"])
        return results

    async def stream_output(self, target: str, config: Dict[str, Any], scan_id: str = None) -> AsyncGenerator[Dict[str, Any], None]:
        # nuclei -u target -jsonl -silent
        
        # Load flags from config
        default_flags = ["-jsonl", "-silent"]
        extra_flags = await self.get_config("tool:nuclei:flags", default_flags)
        
        cmd_list = ["nuclei", "-u", target] + extra_flags
        command = shlex.join(cmd_list)
        
        yield {"type": "log", "data": f"[*] Starting Nuclei on {target}..."}
        
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
                        # Nuclei JSON: template-id, info.severity, matched-at
                        yield {"type": "result", "data": data}
                        
                        name = data.get("info", {}).get("name", "Unknown")
                        severity = data.get("info", {}).get("severity", "info")
                        yield {"type": "log", "data": f"[Nuclei] [{severity.upper()}] {name}"}
                    except json.JSONDecodeError:
                        yield {"type": "log", "data": f"[Nuclei] (Raw) {decoded}"}

            await process.wait()
            yield {"type": "log", "data": "[*] Nuclei Complete."}

        except asyncio.CancelledError:
            yield {"type": "error", "data": "Nuclei cancelled."}
            raise
        except Exception as e:
            yield {"type": "error", "data": f"Nuclei Failed: {e}"}
