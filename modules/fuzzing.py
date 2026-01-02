import asyncio
import os
import json
import tempfile
from rich.console import Console

console = Console()

SECLISTS_PATH = "/usr/share/seclists"

# User-defined presets
PRESETS = {
    "deep": {
        "wordlist": "Discovery/Web-Content/directory-list-2.3-big.txt",
        "flags": [
            "-fc", "400,401,402,403,404,429,500,501,502,503",
            "-recursion", "-recursion-depth", "2",
            "-e", ".html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db",
            "-ac", "-c", "-t", "100", "-r"
        ],
        "headers": [
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
            "X-Forwarded-For: 127.0.0.1",
            "X-Originating-IP: 127.0.0.1", 
            "X-Forwarded-Host: localhost"
        ]
    },
    "standard": {
       "wordlist": "Discovery/Web-Content/directory-list-2.3-big.txt",
       "flags": [
            "-fc", "401,403,404",
            "-recursion", "-recursion-depth", "2",
            "-e", ".html,.php,.txt,.pdf",
            "-ac", "-r", "-t", "60", "--rate", "100", "-c"
       ],
       "headers": [
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0"
       ]
    }
}

async def run_ffuf(target_url, preset_name="standard", broadcast_callback=None, scan_id=None, custom_wordlist=None):
    """
    Runs FFUF against a target URL using a specified preset.
    """
    preset = PRESETS.get(preset_name, PRESETS["standard"])
    wordlist_path = ""
    
    if preset_name == "custom" and custom_wordlist:
        wordlist_path = os.path.join(SECLISTS_PATH, "Discovery/Web-Content", custom_wordlist)
        # For custom, we default to standard flags as a base
        preset = PRESETS["standard"].copy()
    else:
        wordlist_path = os.path.join(SECLISTS_PATH, preset["wordlist"])
    
    # Construct command
    cmd_parts = ["ffuf"]
    
    # Wordlist
    cmd_parts.extend(["-w", wordlist_path])
    
    # Target (Ensure 'FUZZ' is present)
    if "FUZZ" not in target_url:
        if target_url.endswith("/"):
            target_url += "FUZZ"
        else:
            target_url += "/FUZZ"
            
    cmd_parts.extend(["-u", target_url])
    
    # Flags
    # Remove -c from flags if present to clean up logs/output for backend execution
    if "-c" in preset.get("flags", []):
        # We need to copy the list so we don't modify the global dictionary permenantly if we want to
        # But here 'preset' is a ref or copy. 
        # Deep copy is safer if we modify it.
        # But for now, just removing it from the list we pass to cmd_parts is safer than modifying the dict.
        pass

    # Better approach: Iterate and add unless it's -c
    for f in preset["flags"]:
        if f != "-c":
            cmd_parts.append(f)
    
    # Headers
    for h in preset["headers"]:
        cmd_parts.extend(["-H", h])
        
    # JSON Output
    fd, output_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    
    cmd_parts.extend(["-o", output_path, "-of", "json"])
    
    cmd_str = " ".join(cmd_parts)
    
    console.print(f"[bold yellow][*] Running FFUF (Preset: {preset_name}) on {target_url}...[/bold yellow]")
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": f"Starting FFUF ({preset_name}) on {target_url}"})
        # Broadcast the raw command for UI display
        await broadcast_callback({"type": "ffuf_command", "command": cmd_str})
        await broadcast_callback({"type": "log", "message": f"Executing: {cmd_str}"})

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        # Log Stderr for debugging
        if stderr and broadcast_callback:
             # Decode and split lines to avoid massive blocks
             err_text = stderr.decode()
             if err_text.strip():
                 await broadcast_callback({"type": "log", "message": f"[FFUF STDERR] {err_text[:200]}..."}) # Truncate

        if process.returncode != 0:
            console.print(f"[bold red][!] FFUF failed with exit code {process.returncode}[/bold red]")
            if broadcast_callback:
                await broadcast_callback({"type": "log", "message": f"[FFUF ERROR] Exit Code: {process.returncode}"})
                if stderr:
                    await broadcast_callback({"type": "log", "message": f"Error Details: {stderr.decode()}"})
            return
            
        results = []
        if os.path.exists(output_path):
            try:
                with open(output_path, 'r') as f:
                    content = f.read()
                    if content.strip():
                        data = json.loads(content)
                        results = data.get('results', [])
                    else:
                         console.print("[!] FFUF output file is empty.")
                         if broadcast_callback:
                             await broadcast_callback({"type": "log", "message": "[!] Warning: FFUF output file was empty."})
            except json.JSONDecodeError as e:
                console.print(f"[!] Failed to decode FFUF JSON: {e}")
                if broadcast_callback:
                    await broadcast_callback({"type": "log", "message": f"[!] Error decoding JSON output: {e}"})
            finally:
                os.remove(output_path)
        else:
            console.print("[!] Output file does not exist.")
            
        console.print(f"[bold green][+] FFUF Complete. Found {len(results)} items.[/bold green]")
        
        if broadcast_callback:
             await broadcast_callback({"type": "status", "message": f"FFUF Complete. Found {len(results)} items."})
             
             # Database Persistence
             from core.models import AsyncSessionLocal, FuzzingResult
             from urllib.parse import urlparse
             from sqlalchemy import select
             
             processed_urls = set()
             
             async with AsyncSessionLocal() as db:
                 for res in results:
                     url = res.get('url')
                     # Re-validate URL
                     if not url: continue
                     
                     # Avoid duplicates in the current batch
                     if url in processed_urls:
                         continue
                     processed_urls.add(url)
                     
                     status = res.get('status')
                     length = res.get('length')
                     
                     # Extract domain
                     parsed = urlparse(url)
                     domain = parsed.netloc
                     
                     # Broadcast
                     msg = f"[{status}] {url} (Size: {length})"
                     await broadcast_callback({"type": "ffuf_result", "message": msg, "data": res})
                     await broadcast_callback({"type": "log", "message": f"[FFUF] {msg}"})
                     
                     # Save to FuzzingResult Table
                     try:
                         # Check if exists
                         exists = await db.execute(select(FuzzingResult).where(FuzzingResult.url == url))
                         if exists.scalar():
                             continue
                             
                         new_result = FuzzingResult(
                             url=url,
                             target_domain=domain,
                             status_code=int(status) if status else 0,
                             content_length=int(length) if length else 0,
                             preset_used=preset_name
                         )
                         db.add(new_result)
                     except Exception as e:
                         console.print(f"[!] DB Error for {url}: {e}")
                 
                 await db.commit()

    except Exception as e:
        console.print(f"[bold red][!] FFUF Error: {e}[/bold red]")
        if broadcast_callback:
            await broadcast_callback({"type": "log", "message": f"Error: {e}"})
