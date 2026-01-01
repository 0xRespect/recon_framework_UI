import asyncio
import os
import yaml
import json
import uuid
from typing import List
from fastapi import FastAPI, BackgroundTasks, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from sqlalchemy.orm import Session
from sqlalchemy import func

# Add current directory to path
import sys
sys.path.append(os.getcwd())

from core.orchestrator import run_subdomain_enumeration_phase, run_quick_scan
from modules.fuzzing import run_ffuf
from core.models import Subdomain, CrawledURL, Vulnerability, init_db, AsyncSessionLocal
from core.db_manager import get_async_session
from core.scan_registry import registry

app = FastAPI(title="Recon Framework Real-time API", version="1.0")
templates = Jinja2Templates(directory="templates")

# --- WebSocket Manager ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                pass

manager = ConnectionManager()

# --- Config & Helpers ---
def load_config(config_path='config.yaml'):
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f) or {}
    except:
        return {}

async def broadcast_wrapper(data):
    """Callback passed to tools to broadcast events."""
    await manager.broadcast(data)

async def run_scan_background(domain: str, scan_id: str):
    """Background task wrapper for Full Scan."""
    registry.register_scan(scan_id)
    config = load_config()
    await broadcast_wrapper({"type": "status", "message": f"Starting Full Scan for {domain} (ID: {scan_id})"})
    try:
        await run_subdomain_enumeration_phase(domain, config, broadcast_callback=broadcast_wrapper, scan_id=scan_id)
        # Note: Phase 1 triggers Phase 2 -> 3 -> 5 automatically in orchestrator
        await broadcast_wrapper({"type": "status", "message": f"Full Scan complete for {domain}"})
    except asyncio.CancelledError:
        await broadcast_wrapper({"type": "status", "message": f"Scan {scan_id} was cancelled."})
    except Exception as e:
        await broadcast_wrapper({"type": "status", "message": f"Scan failed: {e}"})
    finally:
        registry.remove_scan(scan_id)

async def run_quick_scan_background(domain: str, scan_id: str):
    """Background task wrapper for Quick Scan."""
    registry.register_scan(scan_id)
    config = load_config()
    await broadcast_wrapper({"type": "status", "message": f"Starting Quick Scan for {domain} (ID: {scan_id})"})
    try:
        await run_quick_scan(domain, config, broadcast_callback=broadcast_wrapper, scan_id=scan_id)
        await broadcast_wrapper({"type": "status", "message": f"Quick Scan complete for {domain}"})
    except asyncio.CancelledError:
        await broadcast_wrapper({"type": "status", "message": f"Scan {scan_id} was cancelled."})
    except Exception as e:
        await broadcast_wrapper({"type": "status", "message": f"Scan failed: {e}"})
    finally:
        registry.remove_scan(scan_id)

# --- Lifespan Events ---
@app.on_event("startup")
async def on_startup():
    await init_db()

# --- Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan/fuzz")
async def start_fuzzing(target_url: str, preset: str, background_tasks: BackgroundTasks, custom_wordlist: str = None):
    scan_id = str(uuid.uuid4())
    # We pass 'broadcast_wrapper' as the callback
    background_tasks.add_task(run_ffuf, target_url, preset, broadcast_wrapper, scan_id, custom_wordlist)
    return {"message": "Fuzzing started", "target": target_url, "preset": preset, "scan_id": scan_id}

@app.post("/scan/{domain}")
async def start_scan(domain: str, background_tasks: BackgroundTasks, scan_type: str = "full"):
    scan_id = str(uuid.uuid4())
    
    if scan_type == "quick":
        background_tasks.add_task(run_quick_scan_background, domain, scan_id)
        mode_msg = "Quick Scan"
    else:
        background_tasks.add_task(run_scan_background, domain, scan_id)
        mode_msg = "Full Scan"
        
    return {"message": f"{mode_msg} started", "domain": domain, "scan_id": scan_id}

@app.post("/cancel-scan/{scan_id}")
async def cancel_scan(scan_id: str):
    success = registry.cancel_scan(scan_id)
    if success:
        await manager.broadcast({"type": "status", "message": f"Scan {scan_id} aborted by user."})
        return {"message": "Scan cancellation initiated", "scan_id": scan_id}
    else:
        # It might be already finished or invalid
        return JSONResponse(status_code=404, content={"message": "Scan ID not found or already finished"})

from pydantic import BaseModel
from modules.vuln_scanning import run_nuclei, run_sqli_scan, run_xss_scan, run_lfi_scan

class ScanVulnRequest(BaseModel):
    domain: str
    scan_type: str  # sqli, xss, lfi
    mode: str       # smart, all

@app.post("/api/scan/vuln")
async def start_vuln_scan(req: ScanVulnRequest, background_tasks: BackgroundTasks, db: AsyncSessionLocal = Depends(get_async_session)):
    from sqlalchemy.future import select
    
    scan_id = str(uuid.uuid4())
    
    # Fetch URLs based on mode
    async with db as session:
        query = select(CrawledURL).filter_by(target_domain=req.domain)
        
        if req.mode == "smart":
            # Filter by tags
            # We assume tags are stored as comma-separated: "xss,sqli"
            if req.scan_type == "sqli":
                query = query.filter(CrawledURL.tags.contains("sqli"))
            elif req.scan_type == "xss":
                query = query.filter(CrawledURL.tags.contains("xss"))
            elif req.scan_type == "lfi":
                query = query.filter(CrawledURL.tags.contains("lfi"))
                
        result = await session.execute(query)
        urls = [u.url for u in result.scalars().all()]
    
    if not urls:
        # If no URLs found for 'smart', maybe fallback or just warn?
        # We'll just run it with empty list, the module will handle logging "No URLs".
        pass
        
    # Launch Background Task
    if req.scan_type == "sqli":
        background_tasks.add_task(run_sqli_scan, urls, req.domain, load_config(), broadcast_wrapper, scan_id)
    elif req.scan_type == "xss":
        background_tasks.add_task(run_xss_scan, urls, req.domain, load_config(), broadcast_wrapper, scan_id)
    elif req.scan_type == "lfi":
        background_tasks.add_task(run_lfi_scan, urls, req.domain, load_config(), broadcast_wrapper, scan_id)
    else:
        raise HTTPException(status_code=400, detail="Invalid scan type")
        
    return {"message": f"Started {req.scan_type.upper()} scan ({req.mode})", "scan_id": scan_id, "target_count": len(urls)}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# --- Data Endpoints (SPA) ---
@app.get("/targets")
async def get_targets(db: AsyncSessionLocal = Depends(get_async_session)):
    from sqlalchemy.future import select
    async with db as session:
        result = await session.execute(select(Subdomain.target_domain).distinct())
        targets = result.scalars().all()
        return {"count": len(targets), "targets": targets}

@app.get("/api/wordlists")
async def get_wordlists():
    """Returns a list of available wordlists in the container."""
    wordlist_dir = "/usr/share/seclists/Discovery/Web-Content"
    try:
        files = [f for f in os.listdir(wordlist_dir) if f.endswith(".txt")]
        # Sort by size or name? Let's sort alpha for now.
        files.sort()
        return {"wordlists": files}
    except Exception as e:
        return {"error": str(e), "wordlists": []}

@app.get("/api/inventory/stats")
async def get_inventory_stats(db: AsyncSessionLocal = Depends(get_async_session)):
    from sqlalchemy.future import select
    from sqlalchemy import func
    async with db as session:
        # Get all distinct domains
        result = await session.execute(select(Subdomain.target_domain).distinct())
        domains = result.scalars().all()
        
        stats = []
        for d in domains:
            # Count subdomains
            res_sub = await session.execute(select(func.count(Subdomain.id)).filter_by(target_domain=d))
            sub_count = res_sub.scalar()
            
            # Count URLs
            res_url = await session.execute(select(func.count(CrawledURL.id)).filter_by(target_domain=d))
            url_count = res_url.scalar()
            
            stats.append({
                "domain": d,
                "subdomains": sub_count,
                "urls": url_count
            })
        return stats

@app.get("/api/inventory/{domain}")
async def get_inventory(domain: str, db: AsyncSessionLocal = Depends(get_async_session)):
    from sqlalchemy.future import select
    async with db as session:
        # Get crawled URLs
        result = await session.execute(select(CrawledURL).filter_by(target_domain=domain).limit(1000)) # Limit for perf
        urls = result.scalars().all()
        data = []
        for u in urls:
            data.append({
                "url": u.url,
                "tool": u.source_tool,
                "tags": u.tags.split(",") if u.tags else []
            })
        return {"domain": domain, "count": len(urls), "urls": data}

@app.get("/api/vulns/{domain}")
async def get_vulns(domain: str, db: AsyncSessionLocal = Depends(get_async_session)):
    from sqlalchemy.future import select
    async with db as session:
        result = await session.execute(select(Vulnerability).filter_by(target_domain=domain))
        vulns = result.scalars().all()
        data = []
        for v in vulns:
            data.append({
                "name": v.name,
                "severity": v.severity,
                "url": v.url,
                "matcher": v.matcher_name,
                "description": v.description
            })
        return {"domain": domain, "vulnerabilities": data}


@app.delete("/api/target/{domain}")
async def delete_target(domain: str, db: AsyncSessionLocal = Depends(get_async_session)):
    from sqlalchemy import delete
    async with db as session:
        # Delete subdomains
        await session.execute(delete(Subdomain).where(Subdomain.target_domain == domain))
        # Delete crawled URLs
        await session.execute(delete(CrawledURL).where(CrawledURL.target_domain == domain))
        # Delete vulnerabilities
        await session.execute(delete(Vulnerability).where(Vulnerability.target_domain == domain))
        await session.commit()
    return {"message": f"Deleted data for {domain}"}

@app.get("/api/export/{format}")
async def export_assets(format: str, domain: str, tag: str = None, db: AsyncSessionLocal = Depends(get_async_session)):
    from sqlalchemy.future import select
    from fastapi.responses import StreamingResponse
    import io
    
    if format not in ["txt"]:
        return JSONResponse(status_code=400, content={"error": "Unsupported format"})
    
    async with db as session:
        # Fetch URLs with optional tag filter
        query = select(CrawledURL).filter_by(target_domain=domain)
        if tag:
            # We use ILIKE logic or similar. Since tags are stored as "xss,sqli", 
            # contains(tag) is sufficient.
            query = query.filter(CrawledURL.tags.contains(tag))
            
        result_urls = await session.execute(query)
        urls = [u.url for u in result_urls.scalars().all()]
        
        # Only include subdomains if NO tag is specified (Full Dump)
        subs = []
        if not tag:
             result_subs = await session.execute(select(Subdomain).filter_by(target_domain=domain))
             subs = [s.subdomain for s in result_subs.scalars().all()]
        
        # Combine unique
        all_assets = sorted(list(set(urls + subs)))
        content = "\n".join(all_assets)
        
        filename = f"{domain}_{tag}.txt" if tag else f"{domain}_full_assets.txt"
        
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

@app.get("/api/view/raw")
async def view_raw_assets(domain: str, db: AsyncSessionLocal = Depends(get_async_session)):
    from sqlalchemy.future import select
    from fastapi.responses import PlainTextResponse
    
    async with db as session:
        # Fetch URLs
        result_urls = await session.execute(select(CrawledURL).filter_by(target_domain=domain))
        urls = [u.url for u in result_urls.scalars().all()]
        
        # Fetch Subdomains
        result_subs = await session.execute(select(Subdomain).filter_by(target_domain=domain))
        subs = [s.subdomain for s in result_subs.scalars().all()]
        
        all_assets = sorted(list(set(urls + subs)))
        content = "\n".join(all_assets)
        return PlainTextResponse(content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
