import asyncio
from rich.console import Console

# --- Smart Environment Setup ---
import os
os.environ['PATH'] = f"{os.path.join(os.path.expanduser('~'), 'go', 'bin')}:{os.path.join(os.path.expanduser('~'), '.local', 'bin')}:{os.environ['PATH']}"
# --- End of Smart Environment Setup ---

console = Console()

async def run_task_wrapper(task, target, config, kwargs):
    """
    Executes a task. Checks if it's async or sync.
    """
    try:
        if asyncio.iscoroutinefunction(task):
             return await task(target, config, **kwargs)
        else:
             # Sync tasks generally don't take callbacks in this framework yet, but we handle basic args
             # Run in executor
             loop = asyncio.get_running_loop()
             return await loop.run_in_executor(None, task, target, config)
    except Exception as e:
        console.print(f"[bold red][!] Error in task '{task.__name__}': {e}[/bold red]")
        return None

async def run_tasks_in_parallel(tasks, target, config, description="Running tasks in parallel...", process_timeout=None, **kwargs):
    """
    Executes a list of tasks concurrently.
    Supports both async coroutines and sync functions.
    Passes additional **kwargs (like broadcast_callback) to the tasks.
    """
    console.print(f"[bold cyan]{description}[/bold cyan]")
    
    coroutines = []
    for task in tasks:
        coroutines.append(run_task_wrapper(task, target, config, kwargs))

    try:
        if process_timeout:
             results = await asyncio.wait_for(asyncio.gather(*coroutines), timeout=process_timeout)
        else:
             results = await asyncio.gather(*coroutines)
    except asyncio.TimeoutError:
        console.print(f"[bold red][!] Timeout reached after {process_timeout} seconds. Some tasks may not have completed.[/bold red]")
        results = []
        return []

    # Filter None results and flatten
    valid_results = [r for r in results if r]
    flat_results = []
    for r in valid_results:
        if isinstance(r, list):
            flat_results.extend(r)
        else:
            flat_results.append(r)

    unique_results = sorted(list(set(flat_results)))
    console.print(f"[bold green][+] Phase completed. Results processed via DB or returned.[/bold green]")
    return unique_results
