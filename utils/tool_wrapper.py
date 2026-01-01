import subprocess
import shlex
import os
import shutil
from rich.console import Console

# --- Smart Environment Setup ---
# Add custom tool directories to the PATH environment variable for this script's session.
# This makes the script's environment aware of where to find the installed tools.
go_bin_dir = os.path.join(os.path.expanduser('~'), 'go', 'bin')
local_bin_dir = os.path.join(os.path.expanduser('~'), '.local', 'bin')
os.environ['PATH'] = f"{go_bin_dir}:{local_bin_dir}:{os.environ['PATH']}"
# --- End of Smart Environment Setup ---


# Initialize a console for rich text output
console = Console()

def run_command(command, timeout=None, stdin_data=None):
    """
    Executes an external command safely and returns its output.

    This function is a wrapper around Python's subprocess module to provide
    a standardized way of running external command-line tools.

    Args:
        command (str): The full command to execute (e.g., "subfinder -d example.com").
        timeout (int, optional): The maximum time in seconds for the command to complete. Defaults to None.
        stdin_data (str, optional): Data to be passed to the command's standard input. Defaults to None.

    Returns:
        str: The standard output (stdout) of the command as a string if successful.
        None: If the command fails, times out, or is not found.
    """
    try:
        # Use shlex.split to correctly handle commands with arguments and quotes
        args = shlex.split(command)
        tool_name = args[0]

        # This is a final check to ensure the tool exists before running it.
        # shutil.which will find the tool if it's in the PATH (which we've modified).
        if not shutil.which(tool_name):
            console.print(f"[bold red][!] Error: Command '{tool_name}' not found. Is it installed correctly and in your PATH?[/bold red]")
            return None

        process = subprocess.run(
            args,
            capture_output=True, # Capture stdout and stderr
            text=True,           # Decode stdout/stderr as text using default encoding
            check=False,         # Do not raise CalledProcessError for non-zero exit codes
            timeout=timeout,     # Apply the specified timeout
            input=stdin_data     # Pass data to standard input if provided
        )

        # Check the return code to see if the command executed successfully
        if process.returncode != 0:
            # If there's an error, print a warning with the first line of stderr
            error_snippet = process.stderr.strip().split('\n')[0] if process.stderr else "No error message."
            console.print(f"[yellow][!] Warning: Command '{command}' finished with exit code {process.returncode}. Error: {error_snippet}[/yellow]")
            # Even if there's an error, return any stdout that might have been produced
            return process.stdout.strip() if process.stdout else None

        # If the command was successful, return its standard output
        return process.stdout.strip()

    except FileNotFoundError:
        # This exception is caught if the command itself (the executable) is not found.
        # shutil.which() should ideally prevent this, but it's a good fallback.
        console.print(f"[bold red][!] Error: Command '{shlex.split(command)[0]}' not found. Please ensure it's installed and accessible in your PATH.[/bold red]")
        return None
    except subprocess.TimeoutExpired as e:
        # This block handles cases where the command runs longer than 'timeout' seconds.
        console.print(f"[bold red][!] Error: Command '{command}' timed out after {timeout} seconds. Returning partial output.[/bold red]")
        # Crucially, we return any standard output collected BEFORE the timeout.
        return e.stdout.strip() if e.stdout else None
    except Exception as e:
        # Catch any other unexpected errors during command execution
        console.print(f"[bold red][!] An unexpected error occurred while running '{command}': {e}[/bold red]")
        return None
