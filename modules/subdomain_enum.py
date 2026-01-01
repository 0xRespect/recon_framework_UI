import asyncio
import os
import shlex
import shutil
from rich.console import Console
from core.db_manager import async_add_subdomain
from core.scan_registry import registry

console = Console()

async def run_tool_streaming(command_list, domain, tool_name, broadcast_callback=None, scan_id=None):
    """
    Executes a command asynchronously, streams output line-by-line,
    intersects DB, broadcasts via WebSocket, and supports Cancellation via Registry.
    """
    command_str = shlex.join(command_list)
    console.print(f"[*] Running {tool_name} for {domain} (ScanID: {scan_id})...")
    
    try:
        # Start subprocess
        process = await asyncio.create_subprocess_shell(
            command_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Register if scan_id provided
        if scan_id:
            registry.add_process(scan_id, process)

        new_subdomains_count = 0

        # Stream output
        while True:
            try:
                line = await process.stdout.readline()
            except Exception:
                # Process might have been killed
                break
                
            if not line:
                break
            
            decoded_line = line.decode('utf-8').strip()
            if decoded_line:
                if domain in decoded_line: 
                     try:
                         added = await async_add_subdomain(domain, decoded_line, tool_name)
                         if added:
                             new_subdomains_count += 1
                             
                         if broadcast_callback:
                             await broadcast_callback({
                                 "type": "subdomain",
                                 "domain": domain,
                                 "subdomain": decoded_line,
                                 "tool": tool_name,
                                 "is_new": added
                             })
                     except Exception as e:
                         pass

                if broadcast_callback:
                     await broadcast_callback({
                         "type": "log",
                         "message": f"[{tool_name}] {decoded_line}"
                     })

        # Wait for process to exit
        await process.wait()
        
        # Check if it was terminated (negative exit code usually)
        if process.returncode != 0:
            console.print(f"[!] {tool_name} process exited with code {process.returncode} (Possibly Terminated)")
        else:
            console.print(f"[+] {tool_name} complete. Added {new_subdomains_count} new subdomains to DB.")

        return []
        
    except asyncio.CancelledError:
        console.print(f"[!] Task for {tool_name} was cancelled by asyncio.")
        # Ensure process is killed if the python task is cancelled
        try:
             process.terminate()
        except: 
             pass
        raise
    except Exception as e:
        console.print(f"[!] Unexpected error in {tool_name}: {e}")
        return []

async def run_subfinder(domain, config, broadcast_callback=None, scan_id=None):
    tool_name = "Subfinder"
    cmd = ["subfinder", "-d", domain, "-silent"]
    return await run_tool_streaming(cmd, domain, tool_name, broadcast_callback, scan_id)

async def run_assetfinder(domain, config, broadcast_callback=None, scan_id=None):
    tool_name = "Assetfinder"
    cmd = ["assetfinder", "--subs-only", domain]
    return await run_tool_streaming(cmd, domain, tool_name, broadcast_callback, scan_id)

async def run_findomain(domain, config, broadcast_callback=None, scan_id=None):
    tool_name = "Findomain"
    cmd = ["findomain", "-t", domain, "-q"]
    return await run_tool_streaming(cmd, domain, tool_name, broadcast_callback, scan_id)
