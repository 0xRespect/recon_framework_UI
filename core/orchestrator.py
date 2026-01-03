# This module acts as the "brain" of the application.
# Refactored to use Asyncio, WebSockets and Scan Cancellation.
# PHASE 1 REFACTOR: Using Providers and Repositories.

import sys
import os
import asyncio
from rich.console import Console

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.task_manager import run_tasks_in_parallel
# Legacy imports (to be phased out)
from modules.content_discovery import run_katana, run_gau
from modules.vuln_scanning import run_nuclei

# New Architecture Imports
from core.registry import registry
from core.repositories.sqlalchemy_repo import SqlAlchemyRepository

console = Console()

# Global Repository (Stateless Factory) REMOVED
# Each async context will create its own repo instance to ensure thread/loop safety with asyncpg.

async def run_provider_wrapper(target, config, provider_name, broadcast_callback=None, scan_id=None):
    """
    Adapter to run a Provider via the generic task manager.
    Handles streaming output, DB persistence via Repository, and WebSocket broadcasting.
    """
    # Instantiate Repo per task execution to ensure correct event loop binding
    repo = SqlAlchemyRepository()
    
    # Normalize target_domain for DB
    db_target_domain = config.get("root_domain")
    if not db_target_domain:
        db_target_domain = target
        if "://" in target:
            parsed = urlparse(target)
            if parsed.hostname:
                db_target_domain = parsed.hostname
    
    print(f"[DEBUG] run_provider_wrapper called for {provider_name} on {target}")
    
    provider = registry.get_provider(provider_name)
    if not provider:
        console.print(f"[!] Provider {provider_name} not found in registry.")
        print(f"[DEBUG] Provider {provider_name} NOT FOUND in registry keys: {list(registry._providers.keys())}")
        return []

    print(f"[DEBUG] Found provider: {provider}")
    
    results = []
    # Determine the type of data this provider returns based on name/phase? 
    # Or strict typing? For now, we infer.
    
    async for item in provider.stream_output(target, config, scan_id):
        if item["type"] == "log":
            if broadcast_callback:
                await broadcast_callback(item) # {"type": "log", ...}
            # Also print to console?
            # console.print(item["data"]) 

        elif item["type"] == "result":
            # Persist Result
            data = item["data"]
            results.append(data)
            
            # Broadcast result so tasks/frontend can see it
            if broadcast_callback:
                await broadcast_callback(item)
            
            # Logic specific to Phase 1 (Subdomains)
            if provider_name in ["Subfinder", "Assetfinder", "Findomain"]:
                # data is subdomain string
                subdomain = data
                is_new = await repo.add_subdomain(target, subdomain, provider_name)
                # We already broadcasted the raw item above, but we might want to send a specific "subdomain" event 
                # or just rely on the new "result" event. 
                # Existing tasks.py logic listens for "subdomain" type with "is_new".
                
                # Let's keep the specific event for backward compatibility / clarity
                if is_new and broadcast_callback:
                    await broadcast_callback({
                        "type": "subdomain",
                        "domain": target,
                        "subdomain": subdomain,
                        "tool": provider_name,
                        "is_new": True
                    })
            
            # Logic for Phase 2 (HTTPX)
            elif provider_name == "HTTPX":
                # data is Dict
                url = data.get("url")
                # status = data.get("status_code")
                if url:
                    # Update is_alive in Subdomains? Or update CrawledURL?
                    # HTTPX usually confirms subdomain is alive.
                    # We can store in Subdomain table if it matches.
                    # Parse hostname from url
                    await repo.update_subdomain_alive(url, is_alive=True)
                    # We might also want to store it as a crawled URL or just Alive Host?
            
            # Logic for Phase 3 (Katana)
            elif provider_name == "Katana":
                 # Katana v1.3.0 returns nested json: data['request']['endpoint']
                 req = data.get("request", {})
                 url = req.get("endpoint")
                 if not url:
                     url = data.get("url")
                 if url:
                     await repo.add_crawled_url(db_target_domain, url, "Katana")
            
            # Logic for Phase 5 (Nuclei)
            elif provider_name == "Nuclei":
                 # data is Dict
                 info = data.get("info", {})
                 name = info.get("name")
                 severity = info.get("severity")
                 matched = data.get("matched-at")
                 matcher = data.get("matcher-name")
                 desc = info.get("description")
                 
                 if name and matched:
                     await repo.add_vulnerability(db_target_domain, name, severity, matched, matcher, desc)
    
    return results

# Wrapper functions to fit `run_tasks_in_parallel`'s expect signature `(target, config, **kwargs)`
async def run_subfinder_adapter(target, config, **kwargs):
    return await run_provider_wrapper(target, config, "Subfinder", **kwargs)

async def run_assetfinder_adapter(target, config, **kwargs):
    return await run_provider_wrapper(target, config, "Assetfinder", **kwargs)

async def run_findomain_adapter(target, config, **kwargs):
    return await run_provider_wrapper(target, config, "Findomain", **kwargs)

async def run_httpx_adapter(targets_list, domain, config, **kwargs):
    # HTTPX needs a list of targets usually.
    # Our provider expects 'target' (string or file).
    # We should write targets_list to a temp file here.
    import tempfile
    
    # Note: run_host_discovery_phase passes (subdomains, domain, config, ...)
    # But run_task_wrapper calls task(target, config, **kwargs)
    # This interface mismatch is tricky. 
    # `run_tasks_in_parallel` iterates `tasks`.
    # Phase 2 usually calls `run_httpx` directly, not via `run_tasks_in_parallel`.
    
    # Let's handle the temp file creation
    fd, temp_path = tempfile.mkstemp(suffix=".txt", text=True)
    try:
        with os.fdopen(fd, 'w') as f:
            for t in targets_list:
                f.write(t + "\n")
        
        # Run provider
        # We pass temp_path as 'target' to the provider
        return await run_provider_wrapper(temp_path, config, "HTTPX", **kwargs)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


async def run_subdomain_enumeration_phase(domain, config, broadcast_callback=None, scan_id=None):
    """Orchestrates Phase 1 (Subdomains) using Providers."""
    console.print(f"\n[bold blue]STARTING PHASE 1: SUBDOMAIN ENUMERATION for {domain} (ID: {scan_id})[/bold blue]\n")
    
    repo = SqlAlchemyRepository()
    # Ensure root domain in DB
    await repo.add_subdomain(domain, domain, "Root")

    process_timeout = config.get('settings', {}).get('process_timeout', 600)
    
    # Use Adapters
    subdomain_tasks = [run_subfinder_adapter, run_assetfinder_adapter, run_findomain_adapter]
    
    await run_tasks_in_parallel(
        subdomain_tasks, domain, config, 
        description="Running subdomain enumeration...",
        process_timeout=process_timeout,
        broadcast_callback=broadcast_callback,
        scan_id=scan_id
    )

    console.print("\n[bold blue]PHASE 1 COMPLETE[/bold blue]\n")
    
    # Trigger Phase 2 (Live Host Discovery)
    await run_host_discovery_phase(domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)
    return []

async def run_host_discovery_phase(domain, config, broadcast_callback=None, scan_id=None, trigger_next_phase=True):
    """Phase 2: Live Host Discovery using HTTPX Provider."""
    console.print(f"\n[bold blue]STARTING PHASE 2: HOST DISCOVERY for {domain} (ID: {scan_id})[/bold blue]\n")
    repo = SqlAlchemyRepository()
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Starting Phase 2: Host Discovery"})

    subdomains = await repo.get_subdomains(domain)
    
    # Run HTTPX Adapter directly (not via task manager needed for single task)
    await run_httpx_adapter(subdomains, domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)

    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Phase 2 Complete"})
    console.print("\n[bold blue]PHASE 2 COMPLETE[/bold blue]\n")
    
    if trigger_next_phase:
        await run_crawling_phase(domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)
    return []

async def run_crawling_phase(domain, config, broadcast_callback=None, scan_id=None):
    """Phase 3: Content Discovery (Legacy Wrappers)."""
    console.print(f"\n[bold blue]STARTING PHASE 3: CRAWLING for {domain} (ID: {scan_id})[/bold blue]\n")
    repo = SqlAlchemyRepository()
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Starting Phase 3: Content Discovery"})
        
    # Get Alive Subdomains
    alive_subs = await repo.get_alive_subdomains(domain)
    
    tasks = []
    # Keep legacy calls for now
    if alive_subs:
        tasks.append(run_katana(alive_subs, domain, config, broadcast_callback, scan_id))
    else:
        console.print("[!] No alive subdomains found for active crawling. Skipping Katana.")
        
    tasks.append(run_gau(None, domain, config, broadcast_callback, scan_id))
    
    await asyncio.gather(*tasks)

    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Phase 3 Complete"})
    console.print("\n[bold blue]PHASE 3 COMPLETE[/bold blue]\n")
    
    await run_vuln_scanning_phase(domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)
    return []

from core.db_manager import get_all_crawled_urls 
# Note: we should move get_all_crawled_urls to Repo, but run_nuclei might need refactor or we update calling logic.

async def run_vuln_scanning_phase(domain, config, broadcast_callback=None, scan_id=None):
    """Phase 5: Vulnerability Scanning (Nuclei)."""
    console.print(f"\n[bold blue]STARTING PHASE 5: VULN SCANNING for {domain} (ID: {scan_id})[/bold blue]\n")
    repo = SqlAlchemyRepository()
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Starting Phase 5: Nuclei Scanning"})
        
    # Collect Targets via Repo
    subdomains = await repo.get_alive_subdomains(domain)
    
    targets = set()
    for sub in subdomains:
        targets.add(f"http://{sub}")
        targets.add(f"https://{sub}")
        
    # Crawled URLs via Repo
    crawled = await repo.get_crawled_urls(domain)
    for url in crawled:
        targets.add(url)
        
    # Using Legacy Nuclei Runner
    await run_nuclei(list(targets), domain, config, broadcast_callback, scan_id)

    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Phase 5 Complete"})
    console.print("\n[bold blue]PHASE 5 COMPLETE[/bold blue]\n")
    return []

async def run_quick_scan(domain, config, broadcast_callback=None, scan_id=None):
    """Quick Scan Methodology (Refactored)."""
    console.print(f"\n[bold green]STARTING QUICK SCAN for {domain} (ID: {scan_id})[/bold green]\n")
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": f"Starting Quick Scan for {domain}"})

    await repo.add_subdomain(domain, domain, "Root")
    
    console.print("[yellow][*] Quick Scan - Phase 1: Subfinder Only[/yellow]")
    # Run Subfinder Adapter specifically
    await run_subfinder_adapter(domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)
    
    console.print("[yellow][*] Quick Scan - Phase 2: Host Discovery[/yellow]")
    await run_host_discovery_phase(domain, config, broadcast_callback, scan_id, trigger_next_phase=False)
    
    console.print("[yellow][*] Quick Scan - Phase 3: Vulnerability Scanning (No Crawling)[/yellow]")
    await run_vuln_scanning_phase(domain, config, broadcast_callback, scan_id)
    
    console.print("\n[bold green]*** Quick Scan Workflow Complete ***[/bold green]")
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Quick Scan Complete"})

