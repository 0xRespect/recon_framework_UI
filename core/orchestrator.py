# This module acts as the "brain" of the application.
# Refactored to use Asyncio, WebSockets and Scan Cancellation.
# PHASE 1 REFACTOR: Using Providers and Repositories.

import sys
import os
from typing import List, Dict, Any, Callable
import asyncio
from rich.console import Console
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.task_manager import run_tasks_in_parallel
from core.rate_limiter import rate_limiter
from loguru import logger
import sys

# Configure logger (optional customization)
logger.remove()
logger.add(sys.stderr, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>")
# Legacy imports (to be phased out)
from modules.content_discovery import run_katana, run_gau
from modules.vuln_scanning import run_nuclei

# New Architecture Imports
from core.registry import registry
from core.repositories.sqlalchemy_repo import SqlAlchemyRepository

# Auto-discover providers on module load
registry.auto_discover()

console = Console()

# Global Repository (Stateless Factory) REMOVED
# Each async context will create its own repo instance to ensure thread/loop safety with asyncpg.

async def run_provider_wrapper(target: str, config: Dict[str, Any], provider_name: str, broadcast_callback: Callable = None, scan_id: str = None):
    """
    Generic wrapper to run a provider, handle broadcasting, and persistence.
    """
    # Factory Logic via Registry
    try:
        # registry.get_provider returns an INSTANCE
        provider = registry.get_provider(provider_name)
    except ValueError:
        print(f"[Orchestrator] Unknown provider: {provider_name}")
        return

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
    
                db_target_domain = parsed.hostname
    
    logger.debug(f"run_provider_wrapper called for {provider_name} on {target}")

    # Rate Limiting
    # Limit concurrent tools per target domain (e.g. 5)
    await rate_limiter.acquire(f"target:{db_target_domain}", limit=5)
    
    async for event in provider.run(target, config):
        # Persistence Logic
        if event.get("type") == "subdomain":
            sub = event["data"].get("subdomain")
            if sub:
                is_new = await repo.add_subdomain(sub, db_target_domain, provider_name)
                event["is_new"] = is_new
        
        elif event.get("type") == "result":
            # For HTTPX -> Live Host
            if provider_name.lower() == "httpx":
                url = event["data"].get("url")
                if url:
                   await repo.update_subdomain_alive(url, db_target_domain)
            
            # For Katana/Gau -> Crawled URL
            elif provider_name.lower() in ["katana", "gau"]:
                 url = event["data"].get("url")
                 # Fallback logic for Katana
                 if not url and "request" in event["data"]:
                     url = event["data"].get("request", {}).get("endpoint")
                 if url:
                     await repo.add_crawled_url(db_target_domain, url, provider_name)
            
            # For Nuclei -> Vulnerability
            elif provider_name.lower() == "nuclei":
                 info = event["data"].get("info", {})
                 name = info.get("name")
                 severity = info.get("severity")
                 matched = event["data"].get("matched-at")
                 matcher = event["data"].get("matcher-name")
                 desc = info.get("description")
                 
                 if name:
                     await repo.add_vulnerability(
                         db_target_domain, 
                         name, 
                         severity, 
                         matched, 
                         matcher, 
                         desc
                     )

        # Broadcast
        if broadcast_callback:
            await broadcast_callback(event)
    
    return [] # Changed from `results` to `[]` as `results` was not defined.

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
    logger.info(f"STARTING PHASE 1: SUBDOMAIN ENUMERATION for {domain} (ID: {scan_id})")
    
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

    logger.info("PHASE 1 COMPLETE")
    
    # Trigger Phase 2 (Live Host Discovery)
    await run_host_discovery_phase(domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)
    return []

async def run_host_discovery_phase(domain, config, broadcast_callback=None, scan_id=None, trigger_next_phase=True):
    """Phase 2: Live Host Discovery using HTTPX Provider."""
    logger.info(f"STARTING PHASE 2: HOST DISCOVERY for {domain} (ID: {scan_id})")
    repo = SqlAlchemyRepository()
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Starting Phase 2: Host Discovery"})

    subdomains = await repo.get_subdomains(domain)
    
    # Run HTTPX Adapter directly (not via task manager needed for single task)
    await run_httpx_adapter(subdomains, domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)

    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Phase 2 Complete"})
    logger.info("PHASE 2 COMPLETE")
    
    if trigger_next_phase:
        await run_crawling_phase(domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)
    return []

async def run_crawling_phase(domain, config, broadcast_callback=None, scan_id=None):
    """Phase 3: Content Discovery (Legacy Wrappers)."""
    logger.info(f"STARTING PHASE 3: CRAWLING for {domain} (ID: {scan_id})")
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
        logger.warning("No alive subdomains found for active crawling. Skipping Katana.")
        
    tasks.append(run_gau(None, domain, config, broadcast_callback, scan_id))
    
    await asyncio.gather(*tasks)

    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Phase 3 Complete"})
    logger.info("PHASE 3 COMPLETE")
    
    await run_vuln_scanning_phase(domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)
    return []

from core.db_manager import get_all_crawled_urls 
# Note: we should move get_all_crawled_urls to Repo, but run_nuclei might need refactor or we update calling logic.

async def run_vuln_scanning_phase(domain, config, broadcast_callback=None, scan_id=None):
    """Phase 5: Vulnerability Scanning (Nuclei)."""
    logger.info(f"STARTING PHASE 5: VULN SCANNING for {domain} (ID: {scan_id})")
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
    logger.info("PHASE 5 COMPLETE")
    return []

async def run_quick_scan(domain, config, broadcast_callback=None, scan_id=None):
    """Quick Scan Methodology (Refactored)."""
    logger.info(f"STARTING QUICK SCAN for {domain} (ID: {scan_id})")
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": f"Starting Quick Scan for {domain}"})

    await repo.add_subdomain(domain, domain, "Root")
    
    logger.info("[*] Quick Scan - Phase 1: Subfinder Only")
    # Run Subfinder Adapter specifically
    await run_subfinder_adapter(domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)
    
    logger.info("[*] Quick Scan - Phase 2: Host Discovery")
    await run_host_discovery_phase(domain, config, broadcast_callback, scan_id, trigger_next_phase=False)
    
    logger.info("[*] Quick Scan - Phase 3: Vulnerability Scanning (No Crawling)")
    await run_vuln_scanning_phase(domain, config, broadcast_callback, scan_id)
    
    logger.info("*** Quick Scan Workflow Complete ***")
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Quick Scan Complete"})

