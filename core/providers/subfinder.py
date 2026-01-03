import asyncio
import shlex
import json
from typing import List, Dict, Any, AsyncGenerator
from .base import BaseProvider

class SubfinderProvider(BaseProvider):
    def __init__(self):
        super().__init__("Subfinder")

    async def run(self, target: str, config: Dict[str, Any], scan_id: str = None) -> List[str]:
        """
        Runs Subfinder and returns a list of found subdomains.
        """
        results = []
        async for item in self.stream_output(target, config, scan_id):
            if item["type"] == "result":
                results.append(item["data"])
        return results

    async def stream_output(self, target: str, config: Dict[str, Any], scan_id: str = None) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Streams subfinder output line by line.
        """
        # subfinder -d domain [dynamic flags]
        
        flags = await self.get_config("tool:subfinder:flags", ["-silent", "-all"])
        # Ensure list
        if not isinstance(flags, list):
             flags = str(flags).split()
             
        cmd_list = ["subfinder", "-d", target] + flags
        command = shlex.join(cmd_list)
        
        yield {"type": "log", "data": f"[*] Starting Subfinder for {target}..."}
        
        try:
            process = await self._run_command(command, scan_id)
            
            # Read stdout line by line
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                decoded = line.decode('utf-8').strip()
                if decoded:
                    # Logic to filter out junk? Subfinder -silent usually gives just domains.
                    yield {"type": "result", "data": decoded}
                    yield {"type": "log", "data": f"[Subfinder] Found: {decoded}"}
            
            await process.wait()
            
            if process.returncode != 0:
                stderr = await process.stderr.read()
                err_msg = stderr.decode().strip()
                yield {"type": "error", "data": f"Subfinder exited with {process.returncode}: {err_msg}"}
            else:
                 yield {"type": "log", "data": "[*] Subfinder Complete."}

        except asyncio.CancelledError:
             yield {"type": "error", "data": "Subfinder cancelled."}
             raise
        except Exception as e:
             yield {"type": "error", "data": f"Subfinder Failed: {e}"}
