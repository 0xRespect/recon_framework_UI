# This module acts as the "brain" of the application.
# Refactored to use Asyncio, WebSockets and Scan Cancellation.

import sys
import os
import asyncio
from rich.console import Console

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.task_manager import run_tasks_in_parallel
from modules.subdomain_enum import run_subfinder, run_assetfinder, run_findomain
from modules.host_discovery import run_httpx
from modules.content_discovery import run_katana, run_gau
from core.db_manager import get_subdomains_for_target, get_alive_subdomains_for_target, async_add_subdomain

console = Console()

async def run_subdomain_enumeration_phase(domain, config, broadcast_callback=None, scan_id=None):
    """Orchestrates the subdomain enumeration phase (Phase 1) asynchronously with Streaming & Cancellation."""
    console.print(f"\n[bold blue]STARTING PHASE 1: SUBDOMAIN ENUMERATION for {domain} (ID: {scan_id})[/bold blue]\n")
    
    # Ensure the target itself is in the DB
    await async_add_subdomain(domain, domain, "Root")

    process_timeout = config.get('settings', {}).get('process_timeout', 600)
    subdomain_tasks = [run_subfinder, run_assetfinder, run_findomain]
    
    # Run tasks passing the callback and scan_id
    await run_tasks_in_parallel(
        subdomain_tasks, domain, config, 
        description="Running subdomain enumeration...",
        process_timeout=process_timeout,
        broadcast_callback=broadcast_callback,
        scan_id=scan_id
    )

    console.print("\n[bold blue]PHASE 1 COMPLETE[/bold blue]\n")
    
    # Trigger Phase 2
    await run_host_discovery_phase(domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)
    
    return []

async def run_host_discovery_phase(domain, config, broadcast_callback=None, scan_id=None, trigger_next_phase=True):
    """Phase 2: Live Host Discovery using HTTPX."""
    console.print(f"\n[bold blue]STARTING PHASE 2: HOST DISCOVERY for {domain} (ID: {scan_id})[/bold blue]\n")
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Starting Phase 2: Host Discovery"})

    subdomains = await get_subdomains_for_target(domain)
    await run_httpx(subdomains, domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)

    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Phase 2 Complete"})
    console.print("\n[bold blue]PHASE 2 COMPLETE[/bold blue]\n")
    
    # Trigger Phase 3
    if trigger_next_phase:
        await run_crawling_phase(domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)
    
    return []

async def run_crawling_phase(domain, config, broadcast_callback=None, scan_id=None):
    """Phase 3: Content Discovery (Crawling & Spidering)."""
    console.print(f"\n[bold blue]STARTING PHASE 3: CRAWLING for {domain} (ID: {scan_id})[/bold blue]\n")
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Starting Phase 3: Content Discovery"})
        
    # Get Alive Subdomains (for Katana)
    alive_subs = await get_alive_subdomains_for_target(domain)
    
    # Run Katana (Active) and GAU (Passive) concurrently
    # Note: GAU runs on the main domain, Katana runs on list of alive subs
    tasks = []
    
    # Task 1: Katana
    if alive_subs:
        tasks.append(run_katana(alive_subs, domain, config, broadcast_callback, scan_id))
    else:
        console.print("[!] No alive subdomains found for active crawling. Skipping Katana.")
        
    # Task 2: GAU
    tasks.append(run_gau(None, domain, config, broadcast_callback, scan_id))
    
    await asyncio.gather(*tasks)

    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Phase 3 Complete"})
    console.print("\n[bold blue]PHASE 3 COMPLETE[/bold blue]\n")
    
    # Trigger Phase 5
    await run_vuln_scanning_phase(domain, config, broadcast_callback=broadcast_callback, scan_id=scan_id)
    
    return []

from modules.vuln_scanning import run_nuclei
from core.db_manager import get_all_crawled_urls

async def run_vuln_scanning_phase(domain, config, broadcast_callback=None, scan_id=None):
    """Phase 5: Vulnerability Scanning (Nuclei)."""
    console.print(f"\n[bold blue]STARTING PHASE 5: VULN SCANNING for {domain} (ID: {scan_id})[/bold blue]\n")
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Starting Phase 5: Nuclei Scanning"})
        
    # Collect Targets
    # 1. Alive Subdomains (as URLs)
    subdomains = await get_alive_subdomains_for_target(domain)
    # Convert to http/https urls if they are just domains
    # Assuming httpx output (is_alive) confirms they are reachable.
    # We might need to guess scheme or check if stored in DB with scheme. 
    # Subdomain table only stores hostname.
    # Better to rely on CrawledURLs which include full URLs found by Katana/GAU.
    # However, Katana might have missed the root of a subdomain if it failed mid-way.
    # Let's add standard http/https prefixes for subdomains to the list to be safe.
    
    targets = set()
    for sub in subdomains:
        targets.add(f"http://{sub}")
        targets.add(f"https://{sub}")
        
    # 2. Crawled URLs
    crawled = await get_all_crawled_urls(domain)
    for url in crawled:
        targets.add(url)
        
    await run_nuclei(list(targets), domain, config, broadcast_callback, scan_id)

    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Phase 5 Complete"})
    console.print("\n[bold blue]PHASE 5 COMPLETE[/bold blue]\n")
    return []

async def run_quick_scan(domain, config, broadcast_callback=None, scan_id=None):
    """
    Runs a Quick Scan Methodology:
    1. Fast Subdomain Enum (Subfinder only)
    2. Host Discovery (HTTPX)
    3. Vuln Scan (Nuclei) on top-level
    Skips deep crawling.
    """
    console.print(f"\n[bold green]STARTING QUICK SCAN for {domain} (ID: {scan_id})[/bold green]\n")
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": f"Starting Quick Scan for {domain}"})

    # 1. Subdomain Enum (Subfinder only)
    # We can reuse the parallel runner but just pass one task for speed if we want, 
    # but the logic in run_subdomain_enumeration_phase runs all 3.
    # Let's run just subfinder manually here for true "quick"ness, or re-use the phase but maybe config it?
    # For now, to be safe and consistent with "Quick", let's just run Subfinder.
    
    # Ensure target in DB
    await async_add_subdomain(domain, domain, "Root")
    
    console.print("[yellow][*] Quick Scan - Phase 1: Subfinder Only[/yellow]")
    await run_subfinder(domain, config, broadcast_callback, scan_id)
    
    # 2. Host Discovery
    console.print("[yellow][*] Quick Scan - Phase 2: Host Discovery[/yellow]")
    # We can reuse the existing phase function as it reads from DB and runs httpx
    await run_host_discovery_phase(domain, config, broadcast_callback, scan_id, trigger_next_phase=False)
    
    # 3. Vuln Scan (Nuclei) directly on found hosts (skipping crawler)
    console.print("[yellow][*] Quick Scan - Phase 3: Vulnerability Scanning (No Crawling)[/yellow]")
    await run_vuln_scanning_phase(domain, config, broadcast_callback, scan_id)
    
    console.print("\n[bold green]*** Quick Scan Workflow Complete ***[/bold green]")
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": "Quick Scan Complete"})

