from .celery_config import celery_app
import asyncio
import redis.asyncio as redis
import json
import os
from typing import Dict, Any

# Connection for publishing inside tasks (avoid sharing async event loop of app)
REDIS_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')

async def publish_log(channel, message):
    try:
        # print(f"[DEBUG] Publishing to {channel} using {REDIS_URL}")
        r = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        await r.publish(channel, json.dumps(message))
        await r.close()
        # print(f"[DEBUG] Published to {channel}")
    except Exception as e:
        print(f"Redis Publish Error: {e}")

@celery_app.task(bind=True)
def task_dummy(self, x, y):
    return x + y

@celery_app.task(bind=True)
def task_vuln_scan(self, target_url: str, config: Dict[str, Any], scan_id: str):
    """
    Executes Vulnerability Scanning (Nuclei) for a single URL.
    """
    async def _runner():
        from core.orchestrator import run_provider_wrapper
        async def broadcast_to_redis(data):
             await publish_log(f"recon:scan:{scan_id}", data)
             await publish_log("recon:updates", data)
        
        await run_provider_wrapper(target_url, config, "Nuclei", broadcast_to_redis, scan_id)

    try:
        asyncio.run(_runner())
        return f"VulnScan completed for {target_url}"
    except Exception as e:
        return f"VulnScan failed: {e}"

@celery_app.task(bind=True)
def task_crawling(self, target_url: str, config: Dict[str, Any], scan_id: str):
    """
    Executes Crawling (Katana) for a single Alive Host.
    Triggers 'endpoint_found' -> VulnScan.
    """
    async def _runner():
        from core.orchestrator import run_provider_wrapper
        async def broadcast_to_redis(data):
             await publish_log(f"recon:scan:{scan_id}", data)
             await publish_log("recon:updates", data)
             
             # REACTIVE: If interesting endpoint found, trigger VulnScan?
             # Or just trigger VulnScan on the main URL after crawling is done?
             # For deep scanning, we might want to scan specific endpoints.
             # For now, let's keep it simple: We crawl to populate DB. 
             # Then we might trigger Nuclei on the *base* URL or on *new param* URLs.
             
             # Let's say we trigger VulnScan on the URL if it has parameters? 
             # Or just log it.
             
             if data.get("type") == "result":
                 # data['data'] contains katana result
                 pass

        await run_provider_wrapper(target_url, config, "Katana", broadcast_to_redis, scan_id)
        
        # After crawling is done (or during?), we trigger Nuclei on the target_url
        # Fire and forget
        task_vuln_scan.delay(target_url, config, scan_id)

    try:
        asyncio.run(_runner())
        return f"Crawling completed for {target_url}"
    except Exception as e:
        return f"Crawling failed: {e}"

@celery_app.task(bind=True)
def task_host_discovery(self, subdomain: str, config: Dict[str, Any], scan_id: str):
    """
    Executes Host Discovery (HTTPX) for a SINGLE subdomain.
    Triggers 'url_found' events potentially.
    """
    async def _runner():
        from core.orchestrator import run_provider_wrapper
        
        async def broadcast_to_redis(data):
             # Log live host info
             await publish_log(f"recon:scan:{scan_id}", data)
             await publish_log("recon:updates", data)
             
             # REACTIVE: If Host is Alive (status_code exists), trigger Crawling
             if data.get("type") == "result":
                 result = data.get("data", {})
                 url = result.get("url")
                 if url:
                     # Check if we should crawl
                     # Trigger Crawling
                     task_crawling.delay(url, config, scan_id)
                     
                     await publish_log("recon:updates", {
                         "type": "log", 
                         "message": f"⚡ Triggering Crawling for {url}"
                     })
        
        # We run HTTPXProvider. Note: Provider Registry must have "HTTPX"
        await run_provider_wrapper(subdomain, config, "HTTPX", broadcast_to_redis, scan_id)

    try:
        asyncio.run(_runner())
        return f"HostDiscovery completed for {subdomain}"
    except Exception as e:
        return f"HostDiscovery failed: {e}"

@celery_app.task(bind=True)
def task_run_provider(self, provider_name: str, target: str, config: Dict[str, Any], scan_id: str):
    """
    Executes a Tool Provider usually for Subdomain Enum (Phase 1).
    """
    print(f"[Worker] Starting {provider_name} for {target}")
    
    async def _runner():
        from core.orchestrator import run_provider_wrapper
        
        async def broadcast_to_redis(data):
            # Publish to generic updates channel
            await publish_log("recon:updates", data)
            await publish_log(f"recon:scan:{scan_id}", data)
            
            # REACTIVE LOGIC: If a NEW subdomain is found, trigger Phase 2
            if data.get("type") == "subdomain" and data.get("is_new", False):
                subdomain = data.get("subdomain")
                # Avoid triggering for wildcard/garbage if necessary
                if subdomain:
                     # Fire and Forget Host Discovery Task
                     # We use .delay() to push to queue
                     task_host_discovery.delay(subdomain, config, scan_id)
                     
                     # Log the trigger
                     await publish_log("recon:updates", {
                         "type": "log",
                         "message": f"⚡ Triggering Host Discovery for {subdomain}"
                     })

        await run_provider_wrapper(target, config, provider_name, broadcast_callback=broadcast_to_redis, scan_id=scan_id)

    try:
        asyncio.run(_runner())
        return f"{provider_name} completed for {target}"
    except Exception as e:
        return f"{provider_name} failed: {e}"
