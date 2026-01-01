import os
import sys
import yaml
import argparse
import asyncio
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from core.orchestrator import run_subdomain_enumeration_phase, run_host_discovery_phase, run_crawling_phase, run_vuln_scanning_phase, run_quick_scan

console = Console()

def display_banner():
    """Displays the tool's banner."""
    banner_text = """
    ██████╗ ███████╗ ██████╗ █████╗ ██╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔══██╗██║   ██║
    ██████╔╝█████╗  ██║     ███████║██║   ██║
    ██╔══██╗██╔══╝  ██║     ██╔══██║██║   ██║
    ██║  ██║███████╗╚██████╗██║  ██║╚██████╔╝
    ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝
                Recon Framework v0.6 (Async)
    """
    console.print(Panel.fit(banner_text, style="bold blue"))

def load_config(config_path='config.yaml'):
    """Loads configuration from the config.yaml file."""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        if config is None:
            config = {}
            
        console.print("[bold green][+] Configuration file loaded successfully.[/bold green]")
        return config
    except FileNotFoundError:
        console.print(f"[bold red][!] Error: Configuration file '{config_path}' not found.[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red][!] Error loading configuration file: {e}[/bold red]")
        sys.exit(1)

def create_output_directory(domain):
    """Creates the output directory."""
    dir_name = f"recon_{domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d%H%M')}"
    try:
        os.makedirs(dir_name, exist_ok=True)
        sub_dirs = ["subs", "hosts", "urls", "vulns", "misc"]
        for sub_dir in sub_dirs:
            os.makedirs(os.path.join(dir_name, sub_dir), exist_ok=True)
        console.print(f"[bold green][+] Output directory created: {dir_name}[/bold green]")
        return dir_name
    except Exception as e:
        console.print(f"[bold red][!] Could not create output directory: {e}[/bold red]")
        sys.exit(1)

async def start_full_scan(domain, config):
    """Helper to run the full pipeline."""
    console.print("\n[yellow][*] Starting Full & Deep Scan Methodology (Background Task)...[/yellow]")
    subdomains = await run_subdomain_enumeration_phase(domain, config)
    if subdomains:
        live_hosts = await run_host_discovery_phase(domain, config)
        if live_hosts:
            urls = await run_crawling_phase(domain, config)
            if urls:
                await run_vuln_scanning_phase(domain, config)
    console.print("\n[bold magenta]*** Full Scan Workflow Complete (Background Task Finished) ***[/bold magenta]")

async def main_menu(domain, config):
    """Displays the main interactive menu in an async loop."""
    
    while True:
        console.print("\n")
        console.print(Panel.fit(f"Current Target: [bold cyan]{domain}[/bold cyan]", title="[yellow]Main Menu (Async)[/yellow]", border_style="yellow"))
        console.print("  [bold green]1.[/bold green] Quick Scan Methodology (Fast Mode)")
        console.print("  [bold green]2.[/bold green] Full & Deep Scan Methodology (Background)")
        console.print("  [bold blue]---------------------------------------------[/bold blue]")
        console.print("  [bold cyan]3.[/bold cyan] Phase 1: Subdomain Enumeration (Background)")
        console.print("  [bold cyan]4.[/bold cyan] Phase 2: Live Host Discovery (Background)")
        console.print("  [bold cyan]5.[/bold cyan] Phase 3: Crawling & URL Gathering (Background)")
        console.print("  [bold cyan]6.[/bold cyan] Phase 4: Vulnerability Scanning (Background)")
        console.print("  [bold blue]---------------------------------------------[/bold blue]")
        console.print("  [bold yellow]u.[/bold yellow] Update Tools (Coming Soon)")
        console.print("  [bold red]0.[/bold red] Exit")
        
        # Non-blocking input handling using run_in_executor
        # Prompt.ask is blocking, so we run it in a thread.
        try:
             choice = await asyncio.to_thread(Prompt.ask, "\n[*] Select an option", choices=["1", "2", "3", "4", "5", "6", "u", "0"], default="2")
        except asyncio.CancelledError:
             break

        if choice == '1':
            console.print("\n[yellow][*] Quick Scan selected...[/yellow]")
            asyncio.create_task(run_quick_scan(domain, config))
            console.print("[green]Quick Scan started in background![/green]")
        
        elif choice == '2':
            # Fire and Forget
            asyncio.create_task(start_full_scan(domain, config))
            console.print("[green]Task started in background! You can continue to use the menu.[/green]")

        elif choice == '3':
            asyncio.create_task(run_subdomain_enumeration_phase(domain, config))
            console.print("[green]Task started in background! You can continue to use the menu.[/green]")
            
        elif choice == '4':
            asyncio.create_task(run_host_discovery_phase(domain, config))
            console.print("[green]Task started in background! You can continue to use the menu.[/green]")

        elif choice == '5':
            asyncio.create_task(run_crawling_phase(domain, config))
            console.print("[green]Task started in background! You can continue to use the menu.[/green]")

        elif choice == '6':
             asyncio.create_task(run_vuln_scanning_phase(domain, config))
             console.print("[green]Task started in background! You can continue to use the menu.[/green]")

        elif choice == '0':
            console.print("\n[bold blue][*] Goodbye![/bold blue]")
            # Cancel all running tasks? Or wait? 
            # For now, just exit, which kills background tasks.
            sys.exit(0)
        else:
            console.print(f"\n[yellow][*] Option '{choice}' will be implemented soon.[/yellow]")

async def main():
    parser = argparse.ArgumentParser(description="An advanced framework for reconnaissance operations (Async).")
    parser.add_argument("domain", help="The target domain (e.g., example.com)")
    
    # Handle case where user runs without args (can't happen with Required arg, but usually good practice)
    # Check sys.argv in if __name__ block instead
    
    args = parser.parse_args()
    
    display_banner()
    
    config_path = 'config.yaml'
    if not os.path.exists(config_path) and os.path.exists(f"../{config_path}"):
        config_path = f"../{config_path}"
        
    config = load_config(config_path)
    
    output_dir = create_output_directory(args.domain)
    # We change directory, so future file operations are relative to this.
    # Be careful with absolute paths if used elsewhere.
    os.chdir(output_dir)
    
    # Start the async menu
    await main_menu(args.domain, config)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: python main.py <domain>")
        sys.exit(1)
        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] User interrupted.")
        sys.exit(0)
