import asyncio
import re
import shlex
from rich.console import Console
from core.db_manager import async_add_crawled_url
from core.scan_registry import registry

console = Console()

# GF-like Patterns (Simplified)
# Source: gf sets
import os
import json
import glob

# Tagging Patterns (Regex)
# Initial hardcoded set (fallback)
PATTERNS = {
    # Security
    "xss": r"(q=|s=|search=|id=|query=|keyword=|token=|select=|lang=)",
    "sqli": r"(id=|select=|union=|order=|where=|limit=|group=|debug=)",
    "lfi": r"(file=|doc=|path=|include=|page=|view=|folder=|root=)",
    "ssrf": r"(url=|uri=|link=|dest=|redirect=|source=|proxy=|host=)",
    "redirect": r"(return=|return_url=|r=|next=|target=|goto=|out=)",
    "secrets": r"(key|secret|token|password|auth|access_key|api_key)",
    
    # Files & Structure
    "login": r"(login|signin|auth|sso|register)",
    "admin": r"(admin|dashboard|panel|root)",
    "api": r"(/api/|v1|graphql|swagger)",
    "upload": r"(upload|import|resume)",
    "debug": r"(test|dev|uat|staging)",
    "backup": r"(\.bak|\.old|\.zip|\.sql)",
    "config": r"(\.xml|\.json|\.yaml|\.conf)",
    "docs": r"(\.pdf|\.xls|\.docx)",
}

# Dynamic Pattern Cache
GF_COMPILED = {}

def load_gf_patterns():
    """Loads patterns from config/gf_patterns/*.json into GF_COMPILED."""
    global GF_COMPILED
    if GF_COMPILED: return
    
    # Base Patterns
    for k, v in PATTERNS.items():
        GF_COMPILED[k] = re.compile(v, re.IGNORECASE)

    # Load from Config
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pattern_dir = os.path.join(base_dir, "config", "gf_patterns")
    
    if not os.path.exists(pattern_dir):
        return

    json_files = glob.glob(os.path.join(pattern_dir, "*.json"))
    console.print(f"[*] Loading {len(json_files)} GF patterns from {pattern_dir}")

    for file in json_files:
        name = os.path.basename(file).replace(".json", "")
        # Avoid overwriting hardcoded critical categories entirely? Or merge?
        # Merge logic could be complex. For now, separate or overwrite.
        # Let's overwrite/add.
        
        try:
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                regex_str = None
                if 'pattern' in data:
                    regex_str = data['pattern']
                elif 'patterns' in data:
                     # Join with OR. Escape special chars if they are simple strings?
                     # GF patterns like "q=" are simple strings.
                     # But some in lists might be regex?
                     # xss.json patterns are simple strings mostly.
                     # Safest is re.escape for list items, unless we detect they are regex.
                     # However, "aws-keys" uses "pattern" (singular) which IS a regex.
                     # "xss" uses "patterns" (plural) which are likely simple strings.
                     # Let's use re.escape for "patterns" list items to be safe and match literals.
                     regex_str = "|".join([re.escape(p) for p in data['patterns']])
                
                if regex_str:
                    flags = 0
                    if 'flags' in data and 'i' in data['flags']:
                        flags |= re.IGNORECASE
                    else:
                        flags |= re.IGNORECASE # Default to ignore case for robustness
                        
                    GF_COMPILED[name] = re.compile(regex_str, flags)
        except Exception as e:
            # console.print(f"[!] Error loading GF pattern {name}: {e}")
            pass

def analyze_url(url):
    """Tags a URL based on loaded GF patterns."""
    if not GF_COMPILED:
        load_gf_patterns()
        
    tags = []
    # Optimization: Check common tags first?
    # Iterate all patterns.
    for tag_name, pattern in GF_COMPILED.items():
        if pattern.search(url):
            tags.append(tag_name)
            
    # Deduplicate and clean
    return ",".join(list(set(tags))) if tags else None

from urllib.parse import urlparse, parse_qs

def get_url_signature(url):
    """
    Generates a signature for a URL to dedup parameters.
    Example: http://site.com/page?id=1&q=2 -> http://site.com/page?id&q
    """
    try:
        parsed = urlparse(url)
        # Sort query params
        query_params = parse_qs(parsed.query)
        sorted_keys = sorted(query_params.keys())
        
        # Reconstruct without values
        # We also ignore http/https difference if desired, but usually keeping scheme is safer/distinct.
        # Signature: netloc + path + param_names
        sig = f"{parsed.netloc}{parsed.path}?" + "&".join(sorted_keys)
        return sig
    except:
        return url

async def process_stream(process, domain, tool_name, broadcast_callback=None):
    """Reads stdout from a process line-by-line, tags, filters duplicates, and saves."""
    count = 0
    seen_signatures = set()
    
    while True:
        try:
            line = await process.stdout.readline()
        except:
            break
        if not line:
            break
            
        url = line.decode('utf-8').strip()
        if url:
            # 1. Smart Deduplication
            # Filter out extensive media types if not done by tool
            if any(url.endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.css', '.woff', '.svg']):
                continue

            # Generate Signature (e.g. page.php?id)
            sig = get_url_signature(url)
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)

            # 2. Analyze & Save
            tags = analyze_url(url)
            added = await async_add_crawled_url(domain, url, tool_name, tags)
            
            if added:
                count += 1
                if broadcast_callback:
                    await broadcast_callback({
                        "type": "crawl",
                        "url": url,
                        "tool": tool_name, # Can add "(filtered)" note if needed
                        "tags": tags.split(",") if tags else []
                    })
                    if tags:
                         await broadcast_callback({
                        "type": "log",
                        "message": f"[{tool_name}] Found interesting URL: {url} [{tags}]"
                    })

    return count

async def run_katana(subdomains, domain, config, broadcast_callback=None, scan_id=None):
    """Runs Katana (Active Crawling)."""
    if not subdomains: return
    
    console.print(f"[*] Running Katana for {len(subdomains)} targets on {domain} (ID: {scan_id})...")
    
    # Input via stdin
    input_data = "\n".join(subdomains).encode()
    
    # -silent: output only urls. -jc: js crawl. -d 2: depth.
    # -headless: use headless browser (more accurate but slower).
    # Since we are in docker, ensure chrome is installed? 
    # Dockerfile has python-slim and no chrome. Headless might fail or fallback.
    # Safe bet: standard mode first. If user wants headless, we need chrome in docker.
    # Dockerfile: FROM python:3.9-slim. No chrome.
    # Command: katana -silent -d 2 -jc (js crawl fallback)
    
    cmd = "katana -silent -d 2 -jc -c 10" 
    
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        if scan_id: registry.add_process(scan_id, process)
        
        # Write stdin
        if process.stdin:
            process.stdin.write(input_data)
            await process.stdin.drain()
            process.stdin.close()
            
        count = await process_stream(process, domain, "Katana", broadcast_callback)
        await process.wait()
        
        console.print(f"[+] Katana complete. Found {count} new URLs.")
        
    except asyncio.CancelledError:
        try: process.terminate()
        except: pass
        raise
    except Exception as e:
        console.print(f"[!] Katana error: {e}")

async def run_gau(subdomains, domain, config, broadcast_callback=None, scan_id=None):
    """Runs GAU (Passive Discovery)."""
    # GAU takes domains, not urls usually.
    # Usage: echo "example.com" | gau
    
    console.print(f"[*] Running GAU for {domain} (ID: {scan_id})...")
    
    # We run GAU on the main domain (includes subdomains usually via --subs)
    # OR we run on specific subdomains.
    # Best practice: Run on target domain with --subs if we want broad coverage, 
    # or iterate list.
    # Let's run on the main target domain to capture everything.
    
    cmd = f"gau {domain} --subs --threads 10"
    
    try:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        if scan_id: registry.add_process(scan_id, process)
        
        count = await process_stream(process, domain, "GAU", broadcast_callback)
        await process.wait()
        
        console.print(f"[+] GAU complete. Found {count} new URLs.")
        
    except asyncio.CancelledError:
        try: process.terminate()
        except: pass
        raise
    except Exception as e:
        console.print(f"[!] GAU error: {e}")
