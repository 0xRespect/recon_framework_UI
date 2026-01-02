import asyncio
from typing import List
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
        
        # High Performance Flags (Optimized for i5-12400F / 16GB RAM)
        concurrency = config.get('nuclei', {}).get('concurrency', 25) # Good match for 12 threads
        bulk_size = config.get('nuclei', {}).get('bulk_size', 20)     # Parallel hosts
        rate_limit = config.get('nuclei', {}).get('rate_limit', 300)  # SSD can handle this easily
        
        # We assume 'nuclei' is in PATH (installed via go install)
        # We explicitly omit -t to use default templates or user should configure ~/.nuclei-config.json
        # Or we can specify common tags like cves, exposures.
        # nuclei -tags cves,exposures,misconfiguration
        
        cmd = f"nuclei -l {temp_path} -jsonl -silent -bs {bulk_size} -c {concurrency} -rate-limit {rate_limit}"
        
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
            line_err = await process.stderr.readline()
            
            if not line and not line_err:
                break
                
            if line_err:
                decoded_err = line_err.decode('utf-8', errors='replace').strip()
                if decoded_err and broadcast_callback:
                     await broadcast_callback({"type": "raw", "message": decoded_err})

            if not line:
                continue

            decoded = line.decode('utf-8').strip()
            if decoded:
                # RAW LOG: Stream everything to the raw console
                if broadcast_callback:
                    await broadcast_callback({"type": "raw", "message": decoded})

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
                line_err = await process_sqlmap.stderr.readline()
                
                if not line and not line_err: break
                
                if line_err:
                     l_err = line_err.decode(errors='replace').strip()
                     if broadcast_callback and l_err:
                         await broadcast_callback({"type": "raw", "message": l_err})

                if not line: continue
                
                l = line.decode(errors='replace').strip()
                
                # RAW LOG
                if broadcast_callback and l:
                    await broadcast_callback({"type": "raw", "message": l})

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
        # We need to construct a list of URLs for Gxss
        # Gxss -p Rxss (Reflected XSS mode)
        # -c 50: Concurrency
        # -v: Verbose (useful for debug logic, but maybe noisy here)
        
        gxss_output = targets_path + ".gxss"
        # Adding timeout command to prevent hanging forever
        # -c 100 for speed
        cmd_gxss = f"cat {targets_path} | timeout 300 Gxss -c 100 -p Rxss -o {gxss_output}"
        
        if broadcast_callback:
            await broadcast_callback({"type": "status", "message": "Checking param reflection with Gxss..."})
             
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
                
        # Helper to stream output
        async def stream_output(proc):
            # Read stdout and stderr concurrently
            async def read_stream(stream, prefix=""):
                if not stream: return
                while True:
                     line = await stream.readline()
                     if not line: break
                     decoded = line.decode('utf-8', errors='replace').rstrip()
                     if decoded:
                         print(f"{prefix}{decoded}") # This goes to sys.stdout -> WebSocket

            await asyncio.gather(
                read_stream(proc.stdout, ""),
                read_stream(proc.stderr, "")
            )

        # Output to JSON for parsing
        dalfox_out = "/tmp/dalfox_result.json" 
        # Added timeout 1800 (30 minutes)
        # REMOVED --silence to show banner/progress
        cmd_dalfox = f"timeout 1800 dalfox file {reflected_path} --format json -o {dalfox_out} --skip-bav --worker 10"
        
        if broadcast_callback:
             await broadcast_callback({"type": "status", "message": "Running Dalfox (Timeout: 30m)..."})
             
        process_dalfox = await asyncio.create_subprocess_shell(
            cmd_dalfox,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Stream the output LIVE
        await stream_output(process_dalfox)
        await process_dalfox.wait()
        
        # Check return code for timeout
        # 124 is the standard exit code for 'timeout' command
        if process_dalfox.returncode == 124:
             if broadcast_callback:
                await broadcast_callback({"type": "log", "message": "[!] XSS Scan TIMED OUT (30m Limit Reached). Results may be partial."})

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
                            # DEBUG: Print raw object to see keys
                            # print(f"[DEBUG] Dalfox Raw JSON: {v}") 
                            
                            # v keys: type, severity, method, param, payload, evidence, url
                            name = f"XSS ({v.get('type')})"
                            severity = v.get('severity', 'high').lower()
                            # Dalfox keys might vary: url, target, request_url
                            url = v.get('url') or v.get('target') or v.get('request_url')
                            
                            if not url or v.get('type') is None:
                                # Skip empty/metadata packets
                                continue

                            url = url or "N/A"
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
                    else:
                        if broadcast_callback:
                            await broadcast_callback({"type": "log", "message": "[XSS] Dalfox produced empty output."})
                            
            except json.JSONDecodeError as e:
                # Common if file is truncated due to timeout
                error_msg = f"[XSS] Output parsing failed (likely timeout truncation): {e}"
                console.print(f"[red]{error_msg}[/red]")
                if broadcast_callback:
                     await broadcast_callback({"type": "log", "message": error_msg})
            except Exception as e:
                if broadcast_callback:
                    await broadcast_callback({"type": "log", "message": f"[XSS] Error parsing Dalfox output: {e}"})

    except Exception as e:
        console.print(f"[red]Error in XSS Pipeline: {e}[/red]")
        if broadcast_callback:
            await broadcast_callback({"type": "log", "message": f"[XSS] Pipeline Error: {e}"})
            
    finally:
        # Cleanup
        if 'targets_path' in locals() and os.path.exists(targets_path): os.remove(targets_path)
        if 'gxss_output' in locals() and os.path.exists(gxss_output): os.remove(gxss_output)
        if 'reflected_path' in locals() and os.path.exists(reflected_path): os.remove(reflected_path)

async def run_open_redirect_scan(urls: List[str], domain: str, config: dict, broadcast_callback=None, scan_id=None):
    """
    Scans for Open Redirect vulnerabilities using `qsreplace` and `httpx`.
    Logic:
    1. Filter URLs for redirect parameters (grep + regex).
    2. Replace parameter values with 'https://evil.com' (using qsreplace).
    3. Check if response redirects to evil.com (httpx -status-code -location -er 'evil.com').
    """
    if not urls:
        if broadcast_callback:
            await broadcast_callback({"type": "log", "message": "[OR] No URLs to scan."})
        return

    work_dir = os.path.join("scans", f"{domain}_{scan_id}")
    os.makedirs(work_dir, exist_ok=True)
    
    urls_file = os.path.join(work_dir, "or_urls.txt")
    redirect_urls_file = os.path.join(work_dir, "redirect_params.txt")
    payload_file = os.path.abspath("loxs/payloads/or.txt")
    final_output = os.path.join(work_dir, "or_results.txt")
    
    # Save Initial URLs
    with open(urls_file, "w") as f:
        for u in urls:
            f.write(f"{u}\n")
            
    if broadcast_callback:
        await broadcast_callback({"type": "log", "message": f"[OR] Filtering {len(urls)} URLs for redirect parameters..."})
        
        # DEBUG: Print first 5 URLs to see what we are working with
        debug_msg = " | ".join(urls[:5])
        await broadcast_callback({"type": "log", "message": f"[DEBUG] Input URLs: {debug_msg}"})

    # Step 1: Filter URLs for potential redirect parameters
    # Using the regex from the user request, ensuring 'url=' is explicitly included given the failure
    regex = "url=|returnUrl=|continue=|dest=|destination=|forward=|go=|goto=|login\?to=|login_url=|logout=|next=|next_page=|out=|g=|redir=|redirect=|redirect_to=|redirect_uri=|redirect_url=|return=|returnTo=|return_path=|return_to=|return_url=|rurl=|site=|target=|to=|uri=|qurl=|rit_url=|jump=|jump_url=|originUrl=|origin=|Url=|desturl=|u=|Redirect=|location=|ReturnUrl=|forward_to=|forward_url=|destination_url=|jump_to=|go_to=|goto_url=|target_url=|redirect_link="
    
    # We use grep via shell pipeline since it's efficient for this specific regex
    # command: cat urls | grep -Pi "regex" > output
    cmd_filter = f"cat {urls_file} | grep -Pi \"{regex}\" > {redirect_urls_file}"
    
    proc = await asyncio.create_subprocess_shell(cmd_filter, shell=True)
    await proc.wait()
    
    # Check if we found anything
    if not os.path.exists(redirect_urls_file) or os.path.getsize(redirect_urls_file) == 0:
        if broadcast_callback:
            await broadcast_callback({"type": "log", "message": "[OR] No parameters found via properties. Switching to Discovery Mode..."})
        
        # FALLBACK: If we only have domains (e.g. https://mock_target:5000), we must GUESS parameters.
        # We will take the original input URLs and append common redirect parameters.
        discovery_params = ["url", "redirect", "next", "target", "dest", "destination", "returnUrl", "to", "u", "r"]
        fuzzed_urls = []
        for u in urls:
             # Ensure we don't double slash
             base = u.rstrip('/')
             for p in discovery_params:
                 # Construct: http://target.com/?url=http://google.com
                 fuzzed_urls.append(f"{base}/?{p}=http://google.com")
        
        # Write these fuzzed URLs to the file 'targets_path' to be used by the checking routine
        # We overwrite redirect_urls_file so the next step uses them
        with open(redirect_urls_file, 'w') as f:
            for fu in fuzzed_urls:
                f.write(fu + "\n")
        
        if broadcast_callback:
             await broadcast_callback({"type": "log", "message": f"[OR] Generated {len(fuzzed_urls)} potential endpoints for fuzzing."})

    # Count filtered URLs
    count_filtered = 0
    with open(redirect_urls_file, 'r') as f:
        lines = f.readlines()
        count_filtered = len(lines)
        
    if broadcast_callback:
        await broadcast_callback({"type": "log", "message": f"[OR] Scanning {count_filtered} URLs..."})
        
    # Step 2: Fuzzing loop
    # We will loop through a few common payloads if the file exists, 
    # or just use a standard 'http://evil.com' check as a base baseline.
    # The user request mentioned: cat params | qsreplace "evil.com" | httpx ...
    
    # Helper to check for redirects
    async def check_payload(payload):
        # We assume local 'evil.com' check here for safety, or use example.com.
        # Ideally, we look for the payload in the location header.
        
        # NOTE: Using 'google.com' as destination verification as per user request snippet
        # "httpx ... -mr google.com"
        
        target_payload = "http://google.com" 
        
        # Pipeline: cat URLs | qsreplace payload | httpx -silent -fr -mr "google.com" -mc 301,302
        # We need to construct this.
        
        # We use 'qsreplace' to inject the payload into all parameter values
        cmd_fuzz = f"cat {redirect_urls_file} | qsreplace \"{target_payload}\" | httpx -silent -fr -mr \"google.com\" -mc 301,302 -status-code -location -no-color"
        
        if broadcast_callback:
             await broadcast_callback({"type": "raw", "message": f"Running: {cmd_fuzz}"})
        
        # Helper to stream output
        async def stream_output(proc):
            async def read_stream(stream, prefix=""):
                if not stream: return
                while True:
                     line = await stream.readline()
                     if not line: break
                     decoded = line.decode('utf-8', errors='replace').rstrip()
                     if decoded:
                         print(f"{prefix}{decoded}") # Intercepted by FastAPI to WS
                         
                         # Check for logic matches inside the stream
                         if "[VULN]" in decoded or "Open Redirect found" in decoded or "301" in decoded or "302" in decoded:
                             # We process it
                             parts = decoded.split()
                             url_found = parts[0]
                             await async_add_vulnerability(domain, "Open Redirect", "medium", url_found, "custom-or-scan", f"Redirects to {target_payload}")
                             
            await asyncio.gather(
                read_stream(proc.stdout, ""),
                read_stream(proc.stderr, "")
            )

        process = await asyncio.create_subprocess_shell(
            cmd_fuzz,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Stream it
        await stream_output(process)
        await process.wait()
                # No more processing here, logic moved to stream_output helper
                pass
                
        # End of scan
        if broadcast_callback:
            await broadcast_callback({"type": "log", "message": "[OR] Open Redirect Scan Complete."})
        pass
                    
        await process.wait()

    # Run check
    await check_payload("http://google.com")
    
    # If explicit payload file exists, we could iterate it, but for 'smart' scan we stick to basic injection
    # For a 'Full' scan we would use the payload file logic.
    
    if broadcast_callback:
        await broadcast_callback({"type": "log", "message": "[OR] Scan complete."})



async def run_lfi_scan(urls, domain, config, broadcast_callback=None, scan_id=None):
    if broadcast_callback:
        await broadcast_callback({"type": "log", "message": "[LFI] Starting LFI Scan..."})
    # TODO: Implement specific LFI checks
    pass
