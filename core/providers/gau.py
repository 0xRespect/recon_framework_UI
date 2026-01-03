
import json
import asyncio
from typing import AsyncGenerator, Dict, Any
from core.providers.base import BaseProvider

class GauProvider(BaseProvider):
    NAME = "gau"

    async def run(self, target: str, config: Dict[str, Any]) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Runs GAU (Get All Urls) against the target.
        """
        # GAU typically runs like: gau example.com
        # We can add --subs if needed, but usually we feed it a single domain.
        
        # Check config for threads/options
        
        default_flags = ["--threads", "10"]
        extra_flags = await self.get_config("tool:gau:flags", default_flags)
        
        cmd = ["gau", target] + extra_flags
        
        # Include subs if configured?
        # cmd.append("--subs") 
        
        # Execute
        async for line in self._run_command(cmd):
            url = line.strip()
            if url:
                yield {
                    "type": "result",
                    "data": {
                        "url": url,
                        "source": "gau",
                        "tool": "gau"
                    }
                }
                # Log occasionally? GAU produces A LOT.
                # Maybe only log every Nth item or just stream results.
                # For now, yield all.
