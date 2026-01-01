import asyncio
import httpx
import sys
import os

# Add local path
sys.path.append(os.getcwd())

from core.db_manager import async_add_subdomain
from core.models import init_db

DOMAIN = "simulated-target.local"
MOCK_URL = "http://172.19.0.3:9000"

async def main():
    print(f"[*] Setting up Simulation for {DOMAIN}...")

    # 0. Setup Environment
    # Add host entry
    try:
        with open("/etc/hosts", "a") as f:
            f.write("\n127.0.0.1 simulated-target.local\n")
        print("[*] Added simulated-target.local to /etc/hosts")
    except PermissionError:
        print("[!] Could not write to /etc/hosts (simulated-target.local resolution might fail)")

    # Start Mock Target
    import subprocess
    print("[*] Starting Mock Target on port 9000...")
    mock_proc = subprocess.Popen(
        ["uvicorn", "mock_target:app", "--host", "0.0.0.0", "--port", "9000"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    await asyncio.sleep(2) # Wait for startup

    try:
        # 1. Initialize DB (ensure tables exist)
        await init_db()
        
        # 2. Seed DB with Root Subdomain
        print(f"[*] Seeding database with {MOCK_URL}...")
        # Note: We add the URL as a subdomain/asset?
        # The Orchestrator expects subdomains in `subdomains` table.
        # Phase 1 will find 'simulated-target.local' if we add it or if tools find it.
        # Since tools won't find it (it's local), we must seed it as a "Root" subdomain.
        await async_add_subdomain(DOMAIN, DOMAIN, "SimulationSeed")
        
        # 3. Trigger Scan via API
        api_url = f"http://localhost:8000/scan/{DOMAIN}"
        print(f"[*] Triggering scan at {api_url}...")
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(api_url)
            if resp.status_code == 200:
                data = resp.json()
                print(f"[+] Scan started successfully! ID: {data.get('scan_id')}")
                print("[!] Go to the Dashboard (http://localhost:8000) to watch the Live Console.")
            else:
                print(f"[!] Failed to start scan: {resp.text}")
                
        # Keep alive for testing?
        # No, the main app runs in a separate process (entrypoint).
        # But we need mock_server to stay alive.
        print("[*] Mock Server running. Press Ctrl+C to stop simulation script (or let it run).")
        # We'll wait indefinitely so mock server stays up for the scan duration
        while True:
            await asyncio.sleep(1)
            
    except asyncio.CancelledError:
        pass
    finally:
        print("[*] Stopping Mock Target...")
        mock_proc.terminate()

if __name__ == "__main__":
    asyncio.run(main())
