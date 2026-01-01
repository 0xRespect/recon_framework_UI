import asyncio
import os
import shlex
from rich.console import Console
from core.db_manager import update_subdomain_alive
from core.scan_registry import registry

console = Console()

async def run_httpx(subdomain_list, domain, config, broadcast_callback=None, scan_id=None):
    """
    Runs httpx asynchronously to check for live hosts.
    Inputs: list of subdomains.
    Outputs: Updates DB is_alive status.
    """
    if not subdomain_list:
        console.print("[!] No subdomains provided for HTTPX.")
        return []

    console.print(f"[*] Running HTTPX for {len(subdomain_list)} subdomains on {domain} (ID: {scan_id})...")
    
    # Prepare Input
    input_data = "\n".join(subdomain_list).encode()

    # Settings
    threads = config.get('settings', {}).get('threads', 50)
    # common_ports = "80,443,8080,8000,8888,8443" 
    # Let's trust httpx default or config
    
    # Command: httpx -silent -threads N
    cmd = f"httpx -silent -threads {threads}"
    
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        if scan_id:
            registry.add_process(scan_id, process)

        # Write to stdin and close it so httpx knows input is done
        # But we want to read stdout concurrently.
        # So we create a task to write stdin
        
        async def write_input():
            try:
                process.stdin.write(input_data)
                await process.stdin.drain()
                process.stdin.close()
            except Exception:
                pass

        writer_task = asyncio.create_task(write_input())
        
        alive_count = 0
        
        # Read stdout
        while True:
            try:
                line = await process.stdout.readline()
            except Exception:
                break
                
            if not line:
                break
                
            decoded_line = line.decode('utf-8').strip()
            if decoded_line:
                # Update DB
                updated = await update_subdomain_alive(decoded_line, is_alive=True)
                if updated:
                    alive_count += 1
                
                # Broadcast
                if broadcast_callback:
                    await broadcast_callback({
                         "type": "subdomain", # Re-using type, or new 'live_host'
                         "domain": domain,
                         "subdomain": decoded_line, # Full URL usually
                         "tool": "HTTPX",
                         "is_new": False # It's an update
                    })
                    await broadcast_callback({
                         "type": "log",
                         "message": f"[ALIVE] {decoded_line}"
                    })

        await process.wait()
        await writer_task # ensure writer finished (it should have quickly)

        console.print(f"[+] HTTPX complete. {alive_count} hosts marked alive.")
        return []

    except asyncio.CancelledError:
        try:
             process.terminate()
        except: 
             pass
        raise
    except Exception as e:
        console.print(f"[!] Error in HTTPX: {e}")
        return []
