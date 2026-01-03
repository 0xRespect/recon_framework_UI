import asyncio
import shlex
import json
from typing import List, Dict, Any, AsyncGenerator
from .base import BaseProvider

class HTTPXProvider(BaseProvider):
    def __init__(self):
        super().__init__("HTTPX")

    async def run(self, target: str, config: Dict[str, Any], scan_id: str = None) -> List[Dict[str, Any]]:
        results = []
        async for item in self.stream_output(target, config, scan_id):
            if item["type"] == "result":
                results.append(item["data"])
        return results

    async def stream_output(self, target: str, config: Dict[str, Any], scan_id: str = None) -> AsyncGenerator[Dict[str, Any], None]:
        # Target usually is a list of subdomains file or a single domain?
        # The existing logic passes a list of subdomains.
        # But BaseProvider.run takes 'target' as string. 
        # We might need to handle 'target' as a file path if it starts with / or create a temp file.
        
        # Assumption: For provider simplicity, 'target' is a FILE PATH containing list of domains/urls.
        # Or if it is a single domain, we just scan that.
        
        # We'll support both: if 'target' looks like a file, use -l, else -u (but httpx takes args)
        
        # construct command
        # httpx -l targets.txt -json -title -tech-detect -status-code
        
        # httpx -l targets.txt [dynamic flags]
        
        extra_flags = await self.get_config("tool:httpx:flags", ["-json", "-title", "-tech-detect", "-status-code", "-silent"])
        if not isinstance(extra_flags, list):
             extra_flags = str(extra_flags).split()
        
        # Performance Config (Legacy or DB?)
        # Let's keep using the passed 'config' dict for timeout/threads as that might be per-scan
        threads = config.get("httpx", {}).get("threads", 50)
        extra_flags.extend(["-threads", str(threads)])
        
        if target.endswith(".txt"):
            cmd_list = ["httpx", "-l", target] + extra_flags
        else:
             # Basic check
            cmd_list = ["httpx", "-u", target] + extra_flags

        command = shlex.join(cmd_list)
        
        yield {"type": "log", "data": f"[*] Starting HTTPX on {target}..."}
        
        try:
            process = await self._run_command(command, scan_id)
            
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                decoded = line.decode('utf-8').strip()
                if decoded:
                    try:
                        # Parse JSON
                        data = json.loads(decoded)
                        # data keys: url, status_code, title, tech, etc.
                        yield {"type": "result", "data": data}
                        
                        # Short log
                        status = data.get("status_code", "N/A")
                        url = data.get("url", "N/A")
                        title = data.get("title", "")
                        yield {"type": "log", "data": f"[HTTPX] {status} {url} [{title}]"}
                    except json.JSONDecodeError:
                        yield {"type": "log", "data": f"[HTTPX] (Raw) {decoded}"}

            await process.wait()
            yield {"type": "log", "data": "[*] HTTPX Complete."}

        except asyncio.CancelledError:
             yield {"type": "error", "data": "HTTPX cancelled."}
             raise
        except Exception as e:
             yield {"type": "error", "data": f"HTTPX Failed: {e}"}
