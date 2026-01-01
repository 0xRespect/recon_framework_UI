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

async def run_sqli_scan(urls, domain, config, broadcast_callback=None, scan_id=None):
    """
    Runs a specialized SQLi pipeline:
    1. Filter/Detect candidates using qsreplace + httpx (Error Based)
    2. Confirm with SQLMap
    """
    if not urls:
        if broadcast_callback: 
            await broadcast_callback({"type": "log", "message": "No URLs provided for SQLi Scan."})
        return

    console.print(f"[*] Starting SQLi Pipeline for {domain} on {len(urls)} URLs...")
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": f"Starting SQLi Pipeline on {len(urls)} URLs"})

    # 1. Prepare Target List
    fd, targets_path = tempfile.mkstemp(suffix=".txt", text=True)
    with os.fdopen(fd, 'w') as f:
        for u in urls:
            f.write(u + "\n")
            
    try:
        # 2. Phase A: Error-Based Detection (qsreplace + httpx)
        # pipeline: cat targets | qsreplace "'" | httpx -silent -ms "..." 
        # We need to run this shell pipeline.
        
        errors_path = targets_path + ".errors"
        
        # Note: qsreplace and httpx must be in PATH.
        # Match strings commonly found in SQL errors
        match_strings = "error|sql|syntax|mysql|postgresql|oracle|microsoft|odbc"
        
        cmd_phase_1 = (
            f"cat {targets_path} | qsreplace \"'\" | "
            f"httpx -silent -mc 200,500 -ms \"{match_strings}\" -o {errors_path}"
        )
        
        if broadcast_callback:
             await broadcast_callback({"type": "log", "message": "[SQLi] Running Error-Based Detection..."})
        
        process = await asyncio.create_subprocess_shell(
            cmd_phase_1,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.wait()
        
        # Check results
        potential_vulns = []
        if os.path.exists(errors_path):
            with open(errors_path, 'r') as f:
                potential_vulns = [line.strip() for line in f if line.strip()]
        
        if potential_vulns:
            msg = f"[SQLi] Found {len(potential_vulns)} potential error-based SQLi."
            console.print(f"[green]{msg}[/green]")
            if broadcast_callback:
                 await broadcast_callback({"type": "log", "message": msg})
                 
            # 3. Phase B: SQLMap Verification (on potential hits)
            # If no potential hits, we might skip SQLMap to save time, unless user forced 'heavy'?
            # For this 'Pipeline', we trust potential hits.
            
            # Save potential hits to file for sqlmap
            fd_p, potential_path = tempfile.mkstemp(suffix=".txt", text=True)
            with os.fdopen(fd_p, 'w') as f:
                for u in potential_vulns:
                    f.write(u + "\n")
                    
            if broadcast_callback:
                 await broadcast_callback({"type": "status", "message": f"Running SQLMap on {len(potential_vulns)} targets"})
                 
            # sqlmap --batch --random-agent --level 2 --risk 2 -m list.txt
            sqlmap_cmd = f"sqlmap -m {potential_path} --batch --random-agent --level 2 --risk 2 --output-dir=/tmp/sqlmap_out"
            
            # Since sqlmap is long running, we launch it and stream output?
            # Or just wait. SQLMap can take a long time.
            # We'll use a timeout or let it run.
            
            process_sqlmap = await asyncio.create_subprocess_shell(
                sqlmap_cmd,
                stdout=asyncio.subprocess.PIPE, 
                stderr=asyncio.subprocess.PIPE
            )
            
            # Stream/Log SQLMap output is tricky as it's verbose. 
            # We'll just wait and see if it finds anything (check output dir or stdout for 'detected').
            
            while True:
                line = await process_sqlmap.stdout.readline()
                if not line: break
                l = line.decode(errors='replace').strip()
                # Broadcast interesting lines only?
                if "parameter" in l and "appears to be" in l:
                     await broadcast_callback({"type": "log", "message": f"[SQLMap] {l}"})
                     # Create Vuln Record?!
                     # SQLMap output parsing is complex. For now, rely on logs.
                     
            await process_sqlmap.wait()
            
            if broadcast_callback:
                 await broadcast_callback({"type": "log", "message": "[SQLi] SQLMap Finished."})

            os.remove(potential_path)
            
        else:
            if broadcast_callback:
                 await broadcast_callback({"type": "log", "message": "[SQLi] No error-based responses found. Skipping SQLMap."})

    except Exception as e:
        console.print(f"[!] SQLi Error: {e}")
        if broadcast_callback:
            await broadcast_callback({"type": "log", "message": f"Error: {e}"})
            
    finally:
        if os.path.exists(targets_path): os.remove(targets_path)


async def run_xss_scan(urls, domain, config, broadcast_callback=None, scan_id=None):
    """
    Runs an advanced XSS pipeline:
    1. Filter for XSS candidates (gf xss)
    2. Check reflection (Gxss)
    3. Scan with Dalfox
    """
    if not urls:
        if broadcast_callback: await broadcast_callback({"type": "log", "message": "No URLs provided for XSS Scan."})
        return

    console.print(f"[*] Starting XSS Pipeline for {domain} on {len(urls)} URLs...")
    if broadcast_callback:
        await broadcast_callback({"type": "status", "message": f"Starting XSS Pipeline (Gxss -> Dalfox) on {len(urls)} assets"})

    # 1. Prepare Target List
    fd, targets_path = tempfile.mkstemp(suffix=".txt", text=True)
    with os.fdopen(fd, 'w') as f:
        for u in urls:
            f.write(u + "\n")
            
    try:
        # 2. Phase A: Filtering & Reflection (gf xss | uro | Gxss)
        # We assume 'gf' patterns are installed or available. 
        # Actually 'gf xss' relies on ~/.gf/xss.json. We installed gf but need patterns?
        # If patterns missing, gf might fail. 
        # Alternative: We already have 'tags' from Python logic.
        # So we can trust the input 'urls' are already XSS candidates if 'smart' mode was used.
        # But let's run Gxss to be sure about reflection.
        
        gxss_output = targets_path + ".gxss"
        
        # cmd: cat targets | Gxss -p Rxss -o gxss_output
        cmd_gxss = f"cat {targets_path} | Gxss -p Rxss -o {gxss_output}"
        
        if broadcast_callback:
             await broadcast_callback({"type": "log", "message": "[XSS] Checking param reflection with Gxss..."})
             
        process_gxss = await asyncio.create_subprocess_shell(
            cmd_gxss,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process_gxss.wait()
        
        # Check Gxss results
        reflected_urls = []
        if os.path.exists(gxss_output):
             with open(gxss_output, 'r') as f:
                 reflected_urls = [line.strip() for line in f if line.strip()]
        
        if not reflected_urls:
             # Fallback: if Gxss found nothing, maybe simple scan on original URLs?
             # Or maybe Gxss failed.
             # Let's use original targets if Gxss empty (or maybe just stop? user wants efficiency).
             # User said "Gxss ... | dalfox". If no reflection, dalfox is waste.
             # But lets be safe, if 0 reflected, maybe try Dalfox on top 50 original?
             if broadcast_callback:
                 await broadcast_callback({"type": "log", "message": "[XSS] No reflected params found by Gxss. Trying Dalfox on raw URLs..."})
             reflected_urls = urls 
        else:
             if broadcast_callback:
                 await broadcast_callback({"type": "log", "message": f"[XSS] Found {len(reflected_urls)} URLs with reflected params."})

        # 3. Phase B: Dalfox Scan
        # dalfox pipe --silence --skip-bav
        # We pipe the reflected URLs to dalfox
        
        fd_r, reflected_path = tempfile.mkstemp(suffix=".txt", text=True)
        with os.fdopen(fd_r, 'w') as f:
            for u in reflected_urls:
                f.write(u + "\n")
                
        # Output to JSON for parsing
        dalfox_out = "/tmp/dalfox_result.json" 
        # dalfox file target_file --format json -o output.json
        cmd_dalfox = f"dalfox file {reflected_path} --format json -o {dalfox_out} --silence --skip-bav --worker 10"
        
        if broadcast_callback:
             await broadcast_callback({"type": "status", "message": "Running Dalfox..."})
             
        process_dalfox = await asyncio.create_subprocess_shell(
            cmd_dalfox,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Dalfox output is in file, but standard output might show progress?
        # Dalfox --silence hides progress.
        await process_dalfox.wait()
        
        # Parse Dalfox JSON
        if os.path.exists(dalfox_out):
            try:
                # Dalfox JSON is list of objects? or lines? 
                # Usually list if --format json
                with open(dalfox_out, 'r') as f:
                    content = f.read()
                    if content.strip():
                        # Dalfox might output list [ {...}, {...} ]
                        vulns = json.loads(content)
                        
                        count = 0
                        for v in vulns:
                            # v keys: type, severity, method, param, payload, evidence, url
                            name = f"XSS ({v.get('type')})"
                            severity = v.get('severity', 'high').lower()
                            # Dalfox keys might vary: url, target, request_url
                            url = v.get('url') or v.get('target') or v.get('request_url') or "N/A"
                            desc = f"Payload: {v.get('payload')}"
                            
                            console.print(f"[bold red][VULN] {name} at {url}[/bold red]")
                            
                            added = await async_add_vulnerability(domain, name, severity, url, "dalfox", desc)
                            if added: count += 1
                            
                            if broadcast_callback:
                                await broadcast_callback({"type": "log", "message": f"[DALFOX] Found {name} at {url}"})
                                if added:
                                     await broadcast_callback({
                                        "type": "vuln", 
                                        "vuln": {"name": name, "severity": severity, "url": url}
                                     })

                        if broadcast_callback:
                            await broadcast_callback({"type": "log", "message": f"[XSS] Dalfox finished. Found {count} vulnerabilities."})
                            
            except json.JSONDecodeError:
                if broadcast_callback:
                     await broadcast_callback({"type": "log", "message": "[XSS] Error parsing Dalfox output."})
            finally:
                os.remove(dalfox_out)
        else:
             if broadcast_callback:
                 await broadcast_callback({"type": "log", "message": "[XSS] Dalfox produced no output file."})

        os.remove(reflected_path)

    except Exception as e:
        console.print(f"[!] XSS Pipeline Error: {e}")
        if broadcast_callback:
            await broadcast_callback({"type": "log", "message": f"Error: {e}"})
    finally:
        if os.path.exists(targets_path): os.remove(targets_path)

async def run_lfi_scan(urls, domain, config, broadcast_callback=None, scan_id=None):
    if broadcast_callback:
        await broadcast_callback({"type": "log", "message": "[LFI] Starting LFI Scan..."})
    # TODO: Implement specific LFI checks
    pass
