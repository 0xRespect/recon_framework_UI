
import json
import asyncio
from typing import AsyncGenerator, Dict, Any
from core.providers.base import BaseProvider

class FfufProvider(BaseProvider):
    NAME = "ffuf"

    async def run(self, target: str, config: Dict[str, Any]) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Runs FFUF against the target URL.
        """
        # FFUF workflow: ffuf -u TARGET/FUZZ -w wordlist.txt -o /dev/stdout -of json
        
        wordlists = config.get("wordlists", {})
        fuzz_wordlist = wordlists.get("fuzzing", "/usr/share/seclists/Discovery/Web-Content/common.txt")
        
        # Ensure target implies fuzzing point or append /FUZZ
        if "FUZZ" not in target:
             # Basic check if it ends with /
             target_fuzz = f"{target.rstrip('/')}/FUZZ"
        else:
             target_fuzz = target
             
        cmd = [
            "ffuf",
            "-u", target_fuzz,
            "-w", fuzz_wordlist,
            "-json", # Output as JSON lines
            "-t", "50", # Threads
            "-mc", "200,204,301,302,307,401,403" # Match codes
        ]
        
        async for line in self._run_command(cmd):
            try:
                data = json.loads(line)
                # FFUF JSON: {"input":{"FUZZ":"admin"},"position":1,"status":301,"length":0,"words":0,"lines":0,"content_type":"","redirectlocation":"/admin/","resultfile":"","url":"http://.../admin","host":"..."}
                
                # Yield Result
                yield {"type": "result", "data": data}
                
                # Log interesting finds
                yield {"type": "log", "data": f"[FFUF] Found: {data.get('url')} (Status: {data.get('status')})"}
                
            except json.JSONDecodeError:
                # FFUF prints banner/progress to stderr usually, but sometimes stdout?
                pass
