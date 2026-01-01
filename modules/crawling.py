# This module is responsible for crawling URLs from live hosts.
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.tool_wrapper import run_command
from rich.console import Console

console = Console()

def run_katana(input_file, config):
    """
    Runs Katana to crawl URLs from a list of live hosts, using flags from the methodology.
    Saves output directly to a file.

    Args:
        input_file (str): Path to the file containing live hosts.
        config (dict): The configuration dictionary.

    Returns:
        str: Path to the output file if successful, None otherwise.
    """
    console.print(f"[yellow][*] Running Katana on {input_file}...[/yellow]")
    output_file = "urls/katana_raw.txt" # Define a specific output file for Katana
    
    # Using flags from the reference bash script: -jc (javascript parsing), -d 2 (crawl depth)
    # Directing output to the specified file using -o flag
    command = f"katana -list {input_file} -silent -jc -d 2 -o {output_file}"
    
    # run_command will execute the command. We don't need its stdout directly here
    # because Katana writes to the file. We just check if the command ran.
    run_command(command) 
    
    # Check if the output file was created and has content
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        with open(output_file, 'r') as f:
            urls_count = len(f.readlines())
        console.print(f"[bold green][+] Katana scan complete. Found {urls_count} URLs. Results saved to {output_file}[/bold green]")
        return output_file # Return the path to the file
    else:
        console.print("[yellow][!] Katana scan completed, but no URLs were found or output file is empty.[/yellow]")
        return None


def run_gau(input_file, config):
    """
    Runs GAU (Get All URLs) to fetch historical URLs from multiple providers.
    This version reads the file and passes its content to stdin, then redirects stdout to a file.

    Args:
        input_file (str): Path to the file containing live hosts.
        config (dict): The configuration dictionary.

    Returns:
        str: Path to the output file if successful, None otherwise.
    """
    console.print(f"[yellow][*] Running GAU on {input_file}...[/yellow]")
    output_file = "urls/gau_raw.txt" # Define a specific output file for GAU
    
    # The '-t' flag for threads has been removed as it's deprecated in newer versions of gau.
    # We will pipe the input_file content to gau and redirect gau's stdout to output_file
    command = f"gau > {output_file}" # GAU will read from stdin and write to output_file
    
    try:
        with open(input_file, 'r') as f:
            input_content = f.read()
    except FileNotFoundError:
        console.print(f"[bold red][!] Input file for GAU not found: {input_file}[/bold red]")
        return None

    # Pass the file content to the command's standard input
    # run_command will execute the command. We don't need its stdout directly here
    # because GAU writes to the file. We just check if the command ran.
    run_command(command, stdin_data=input_content)
    
    # Check if the output file was created and has content
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        with open(output_file, 'r') as f:
            urls_count = len(f.readlines())
        console.print(f"[bold green][+] GAU scan complete. Found {urls_count} URLs. Results saved to {output_file}[/bold green]")
        return output_file # Return the path to the file
    else:
        console.print("[yellow][!] GAU scan completed, but no URLs were found or output file is empty.[/yellow]")
        return None


# This is a main block for testing this module individually
if __name__ == '__main__':
    test_hosts = ["https://scanme.nmap.org", "http://example.com"]
    test_file = "test_hosts.txt"
    with open(test_file, "w") as f:
        for host in test_hosts:
            f.write(f"{host}\n")

    console.print(f"[bold blue]--- Running Test for crawling.py ---[/bold blue]")
    test_config = {}
    if not os.path.exists("urls"): # Ensure 'urls' directory exists for testing
        os.makedirs("urls")

    katana_output_file = run_katana(test_file, test_config)
    if katana_output_file:
        print(f"\nKatana Results saved to: {katana_output_file}")
    else:
        print("\nKatana found no URLs.")

    gau_output_file = run_gau(test_file, test_config)
    if gau_output_file:
        print(f"\nGAU Results saved to: {gau_output_file}")
    else:
        print("\nGAU found no URLs.")
    
    # Clean up test files and output files
    os.remove(test_file)
    if os.path.exists("urls/katana_raw.txt"):
        os.remove("urls/katana_raw.txt")
    if os.path.exists("urls/gau_raw.txt"):
        os.remove("urls/gau_raw.txt")
