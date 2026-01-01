import asyncio
import os
import json
import tempfile
from rich.console import Console
from core.db_manager import async_add_vulnerability
from core.scan_registry import registry

console = Console()

async def run_nuclei(urls, domain, config, broadcast_callback=None, scan_id=None):
    """
    Runs Nuclei against the collected URLs (and subdomains).
    """
    if not urls:
        console.print("[!] No URLs found for Nuclei scanning.")
        return

    console.print(f"[*] Starting Nuclei Scan for {domain} (ID: {scan_id}) on {len(urls)} targets...")
    
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": f"Starting Nuclei Scan on {len(urls)} assets"})

    # Create temporary file for targets
    # We want to scan distinct URLs + subdomains
    # Input urls is list of strings
    
    try:
        # Create temp file
        # Using tempfile.NamedTemporaryFile delete=False so we can pass path to docker/subprocess
        # Note: If running in docker, /tmp is inside container. 
        # If running purely local, it's local.
        # We assume code runs inside container or environment where 'nuclei' is installed.
        
        fd, temp_path = tempfile.mkstemp(suffix=".txt", text=True)
        with os.fdopen(fd, 'w') as f:
            for u in urls:
                f.write(u + "\n")
                
        # Nuclei Command
        # -l : target list
        # -t : templates (optional, or default)
        # -json : json output
        # -o : output file (optional, or collect stdout)
        # -silent : less noise
        # -bs 50 : bulk size
        # -c 30 : concurrency
        # -sr : scan output (show results)
        
        # We prefer reading stdout in streaming fashion if possible, 
        # OR letting nuclei write to a JSON file and reading it.
        # Reading stdout line-by-line as JSON is good for streaming.
        
        # Default flags
        concurrency = config.get('nuclei', {}).get('concurrency', 30)
        bulk_size = config.get('nuclei', {}).get('bulk_size', 50)
        
        # We assume 'nuclei' is in PATH (installed via go install)
        # We explicitly omit -t to use default templates or user should configure ~/.nuclei-config.json
        # Or we can specify common tags like cves, exposures.
        # nuclei -tags cves,exposures,misconfiguration
        
        cmd = f"nuclei -l {temp_path} -jsonl -silent -bs {bulk_size} -c {concurrency}"
        
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        if scan_id:
            registry.add_process(scan_id, process)

        # Stream Output
        count = 0
        while True:
            line = await process.stdout.readline()
            if not line:
                break
                
            decoded = line.decode('utf-8').strip()
            if decoded:
                try:
                    vuln_data = json.loads(decoded)
                    # Example Nuclei JSON: 
                    # {"template-id":"git-config","info":{"name":"Git Config Context","severity":"low"},"matcher-name":"git-config","type":"http","host":"https://example.com","matched-at":"https://example.com/.git/config",...}
                    
                    name = vuln_data.get('info', {}).get('name', 'Unknown')
                    severity = vuln_data.get('info', {}).get('severity', 'info')
                    url = vuln_data.get('matched-at', vuln_data.get('host'))
                    matcher = vuln_data.get('matcher-name')
                    desc = vuln_data.get('info', {}).get('description')
                    
                    
                    # Print to Console (Always)
                    vuln_str = f"[VULN] [{severity.upper()}] {name} at {url}"
                    console.print(f"[bold red]{vuln_str}[/bold red]")

                    # Save to DB
                    added = await async_add_vulnerability(domain, name, severity, url, matcher, desc)
                    
                    if added:
                        count += 1
                        
                    # Always Broadcast Log for visibility in Web UI Live Console
                    if broadcast_callback:
                         # Send log
                        await broadcast_callback({
                            "type": "log",
                            "message": vuln_str
                        })
                        
                        # Only send 'vuln' event (stats update) if new
                        if added:
                            await broadcast_callback({
                                "type": "vuln",
                                "vuln": {
                                    "name": name,
                                    "severity": severity,
                                    "url": url
                                }
                            })

                except json.JSONDecodeError:
                    # Not JSON, might be error or info message
                    console.print(f"[!] Nuclei output (non-JSON): {decoded}")
                    pass

        # Wait for process to complete
        await process.wait()
        
        # Check stderr for errors
        stderr_output = await process.stderr.read()
        if stderr_output:
            stderr_text = stderr_output.decode('utf-8')
            if stderr_text.strip():
                console.print(f"[!] Nuclei stderr: {stderr_text[:500]}")
        
        console.print(f"[+] Nuclei Scan Complete. Found {count} vulnerabilities.")
        
        if broadcast_callback:
            await broadcast_callback({
                "type": "status",
                "message": f"Nuclei scan complete. Found {count} vulnerabilities"
            })

    except asyncio.CancelledError:
        try: process.terminate()
        except: pass
        raise
    except Exception as e:
        console.print(f"[!] Nuclei Error: {e}")
        import traceback
        console.print(traceback.format_exc())
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
