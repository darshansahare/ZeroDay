"""
ZeroDay Arena: Main Application Server
Autonomous Adversarial Security & Self-Healing Agent Platform
FastAPI server serving cyber arena dashboard, REST APIs, and real-time WebSockets.
"""

import os
from pathlib import Path
import json
import asyncio
from typing import Set, Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

from engine.orchestrator import ArenaOrchestrator
from engine.ast_scanner import ASTSecurityScanner
from app.core.auth import (
    require_admin_auth,
    verify_websocket_auth,
    create_session,
    is_request_https,
    validate_session,
    SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME,
)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.active_connections.discard(connection)

manager = ConnectionManager()

# Event dispatcher connecting orchestrator to WebSockets
async def ws_event_dispatcher(event: Dict[str, Any]):
    await manager.broadcast(event)

orchestrator = ArenaOrchestrator(event_callback=ws_event_dispatcher)
scanner = ASTSecurityScanner()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure baseline sandbox is intact
    if not os.path.exists("target_app/app.py") and os.path.exists("target_app/app_backup.py"):
        orchestrator.reset_sandbox()
    yield
    # Shutdown

app = FastAPI(
    title="ZeroDay Arena",
    description="Autonomous Adversarial Security & Self-Healing Agent Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Enable CORS safely for frontend development and local access
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files and built React bundle
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

if os.path.exists("static_dist/assets"):
    app.mount("/assets", StaticFiles(directory="static_dist/assets"), name="assets")

from app.api.routes import router as remediation_router

# Mount modular remediation engine routes at /api
app.include_router(remediation_router, prefix="/api")

def _serve_spa_index(request: Optional[Request] = None, status_code: int = 200) -> FileResponse:
    dist_index = os.path.join("static_dist", "index.html")
    path = dist_index if os.path.exists(dist_index) else os.path.join("static", "index.html")
    response = FileResponse(path, status_code=status_code)
    if request is not None:
        session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
        if not session_cookie or not validate_session(session_cookie):
            session_token, csrf_token = create_session()
            secure_cookie = is_request_https(request)
            response.set_cookie(
                key=SESSION_COOKIE_NAME,
                value=session_token,
                httponly=True,
                secure=secure_cookie,
                samesite="lax",
                max_age=86400,
                path="/",
            )
            response.set_cookie(
                key=CSRF_COOKIE_NAME,
                value=csrf_token,
                httponly=False,
                secure=secure_cookie,
                samesite="lax",
                max_age=86400,
                path="/",
            )
    return response


@app.get("/")
async def serve_landing(request: Request):
    """Serve the enterprise SaaS landing page (React SPA)."""
    return _serve_spa_index(request)


@app.get("/arena")
async def serve_arena(request: Request):
    """Serve the ZeroDay Arena target selection screen (React SPA)."""
    return _serve_spa_index(request)


@app.get("/arena/runs/{run_id}")
async def serve_arena_run(run_id: str, request: Request):
    """Serve the ZeroDay Arena run workspace (React SPA)."""
    return _serve_spa_index(request)


@app.get("/benchmarks")
async def serve_benchmarks(request: Request):
    """Serve the ZeroDay Benchmarks suite overview page (React SPA) or JSON API response if requested."""
    accept = request.headers.get("accept", "")
    if "application/json" in accept and "text/html" not in accept:
        from app.api.routes import get_benchmarks_overview
        return get_benchmarks_overview()
    return _serve_spa_index(request)


@app.get("/benchmarks/{benchmark_id}")
async def serve_benchmark_detail(benchmark_id: str, request: Request):
    """Serve the ZeroDay Benchmark case inspection workspace (React SPA) or JSON API response if requested."""
    accept = request.headers.get("accept", "")
    if "application/json" in accept and "text/html" not in accept:
        from app.api.routes import api_get_single_benchmark
        return api_get_single_benchmark(benchmark_id)
    return _serve_spa_index(request)


@app.get("/documentation")
async def serve_documentation(request: Request):
    """Serve the ZeroDay Technical Documentation Hub (React SPA)."""
    return _serve_spa_index(request)


@app.get("/documentation/{topic_slug}")
async def serve_documentation_topic(topic_slug: str, request: Request):
    """Serve individual ZeroDay documentation topic pages (React SPA)."""
    return _serve_spa_index(request)


@app.get("/docs")
async def serve_docs():
    """Redirect legacy /docs to canonical /documentation route."""
    return RedirectResponse(url="/documentation", status_code=301)


@app.get("/docs/{topic_slug}")
async def serve_docs_topic(topic_slug: str):
    """Redirect legacy /docs/{topic_slug} to canonical /documentation/{topic_slug} route."""
    return RedirectResponse(url=f"/documentation/{topic_slug}", status_code=301)


@app.get("/hackathon")
async def serve_hackathon(request: Request):
    """Serve the ZeroDay Hackathon Showcase & Knowledge Page (React SPA)."""
    return _serve_spa_index(request)


@app.get("/robots.txt")
async def serve_robots_txt():
    """Serve robots.txt crawler directives."""
    for base in ["static_dist", "static"]:
        cand = os.path.join(base, "robots.txt")
        if os.path.isfile(cand):
            return FileResponse(cand, media_type="text/plain; charset=utf-8")
    raise HTTPException(status_code=404, detail="robots.txt not found")


@app.get("/sitemap.xml")
async def serve_sitemap_xml():
    """Serve sitemap.xml for search engines."""
    for base in ["static_dist", "static"]:
        cand = os.path.join(base, "sitemap.xml")
        if os.path.isfile(cand):
            return FileResponse(cand, media_type="application/xml; charset=utf-8")
    raise HTTPException(status_code=404, detail="sitemap.xml not found")


@app.get("/llms.txt")
async def serve_llms_txt():
    """Serve llms.txt standard manifest for LLMs and AI search engines."""
    for base in ["static_dist", "static"]:
        cand = os.path.join(base, "llms.txt")
        if os.path.isfile(cand):
            return FileResponse(cand, media_type="text/plain; charset=utf-8")
    raise HTTPException(status_code=404, detail="llms.txt not found")


@app.get("/llms-full.txt")
async def serve_llms_full_txt():
    """Serve llms-full.txt comprehensive context file for LLMs."""
    for base in ["static_dist", "static"]:
        cand = os.path.join(base, "llms-full.txt")
        if os.path.isfile(cand):
            return FileResponse(cand, media_type="text/plain; charset=utf-8")
    raise HTTPException(status_code=404, detail="llms-full.txt not found")

# Mount fallback router at root for legacy un-prefixed API routes
app.include_router(remediation_router, prefix="")

@app.get("/solid_red_agent.jpg")
async def serve_solid_red_agent():
    for path in ["static_dist/solid_red_agent.jpg", "static/solid_red_agent.jpg"]:
        if os.path.exists(path):
            return FileResponse(path)
    raise HTTPException(status_code=404, detail="Agent image not found")

@app.get("/red_mascot.jpg")
async def serve_red_mascot():
    for path in ["static_dist/red_mascot.jpg", "static/red_mascot.jpg", "static_dist/solid_red_agent.jpg"]:
        if os.path.exists(path):
            return FileResponse(path)
    raise HTTPException(status_code=404, detail="Mascot image not found")

@app.get("/blue_mascot.jpg")
async def serve_blue_mascot():
    for path in ["static_dist/blue_mascot.jpg", "static/blue_mascot.jpg"]:
        if os.path.exists(path):
            return FileResponse(path)
    raise HTTPException(status_code=404, detail="Mascot image not found")


@app.get("/api/status")
async def get_arena_status():
    """Retrieve current system status, AST vulnerability scan, and sandbox state."""
    report = scanner.scan_file("target_app/app.py")
    diff_info = orchestrator.get_current_diff()
    return {
        "status": "online",
        "service": "ZeroDay Arena Autonomous Defense Platform",
        "llm_engine": "nvidia/Nemotron-3-Nano-30B-A3B",
        "provider": "Nebius Token Factory",
        "sandbox_modified": diff_info["is_modified"],
        "lines_added": diff_info["lines_added"],
        "lines_removed": diff_info["lines_removed"],
        "ast_summary": report.get("summary", {}),
        "total_routes": report.get("routes_count", 0),
        "finops": {
            "total_tokens": orchestrator.total_prompt_tokens + orchestrator.total_completion_tokens,
            "cost_usd": round(orchestrator.total_cost_usd, 6)
        }
    }

@app.get("/api/diff")
async def get_diff():
    """Return unified diff comparing clean baseline vs current sandbox code."""
    return orchestrator.get_current_diff()

@app.get("/api/target/source")
async def get_target_source():
    """Return raw source code of the active target microservice."""
    if os.path.exists("target_app/app.py"):
        with open("target_app/app.py", "r", encoding="utf-8") as f:
            content = f.read()
        return {"content": content, "filename": "target_app/app.py"}
    raise HTTPException(status_code=404, detail="Target app source not found")

@app.post("/api/reset", dependencies=[Depends(require_admin_auth)])
async def reset_sandbox():
    """Trigger deterministic rollback restoring target_app/app.py from app_backup.py."""
    result = orchestrator.reset_sandbox()
    diff = orchestrator.get_current_diff()
    await manager.broadcast({
        "event_type": "SANDBOX_RESET",
        "stage": 0,
        "stage_name": "RESET",
        "status": "completed",
        "message": "Sandbox microservice reverted to baseline vulnerable state.",
        "data": diff
    })
    return result

@app.post("/api/run", dependencies=[Depends(require_admin_auth)])
async def trigger_duel():
    """Trigger autonomous 6-stage arena duel asynchronously."""
    asyncio.create_task(orchestrator.run_full_duel())
    return {"message": "Autonomous duel launched in background", "status": "initiated"}

@app.post("/api/scan", dependencies=[Depends(require_admin_auth)])
async def trigger_scan():
    """Run AST static scan on demand."""
    report = scanner.scan_file("target_app/app.py")
    await manager.broadcast({
        "event_type": "STAGE_COMPLETE",
        "stage": 1,
        "stage_name": "RECON",
        "status": "completed",
        "message": f"On-demand AST scan mapped {report.get('routes_count', 0)} routes and found {len(report.get('findings', []))} vulnerabilities.",
        "data": report
    })
    return report

@app.post("/reset", dependencies=[Depends(require_admin_auth)])
async def alternate_reset_sandbox():
    """Un-prefixed alternate route for resetting sandbox."""
    return await reset_sandbox()

@app.post("/run", dependencies=[Depends(require_admin_auth)])
async def alternate_trigger_duel():
    """Un-prefixed alternate route for triggering duel."""
    return await trigger_duel()

@app.post("/scan", dependencies=[Depends(require_admin_auth)])
async def alternate_trigger_scan():
    """Un-prefixed alternate route for triggering AST scan."""
    return await trigger_scan()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Real-time WebSocket endpoint for streaming cyber arena events,
    terminal telemetry, FinOps meters, and code diff transitions.
    """
    await manager.connect(websocket)
    # Send initial greeting & state
    diff_info = orchestrator.get_current_diff()
    report = scanner.scan_file("target_app/app.py")
    await websocket.send_json({
        "event_type": "SYSTEM_CONNECT",
        "stage": 0,
        "stage_name": "READY",
        "status": "ready",
        "message": "Connected to ZeroDay Arena Autonomous SOC-1 Gateway.",
        "data": {
            "diff": diff_info,
            "scan": report,
            "llm": "nvidia/Nemotron-3-Nano-30B-A3B (Nebius Token Factory)"
        }
    })

    try:
        while True:
            text = await websocket.receive_text()
            try:
                cmd = json.loads(text)
            except Exception:
                cmd = {"action": text}

            action = cmd.get("action", "")
            if action in ("start_arena", "reset_sandbox", "run_scan"):
                if not verify_websocket_auth(websocket):
                    await websocket.send_json({
                        "event_type": "ERROR",
                        "status": "unauthorized",
                        "message": "Authentication required for privileged arena actions."
                    })
                    continue
            if action == "start_arena":
                # Launch full autonomous duel
                asyncio.create_task(orchestrator.run_full_duel())
            elif action == "reset_sandbox":
                orchestrator.reset_sandbox()
                diff = orchestrator.get_current_diff()
                await manager.broadcast({
                    "event_type": "SANDBOX_RESET",
                    "stage": 0,
                    "stage_name": "RESET",
                    "status": "completed",
                    "message": "Sandbox reverted to vulnerable baseline snapshot.",
                    "data": diff
                })
            elif action == "run_scan":
                rep = scanner.scan_file("target_app/app.py")
                await websocket.send_json({
                    "event_type": "STAGE_COMPLETE",
                    "stage": 1,
                    "stage_name": "RECON",
                    "status": "completed",
                    "message": "AST Scan Complete",
                    "data": rep
                })
            elif action == "ping":
                await websocket.send_json({"event_type": "PONG", "timestamp": "now"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        manager.disconnect(websocket)

@app.get("/{full_path:path}")
async def catch_all_frontend_or_404(full_path: str):
    """
    Catch-all route for unknown paths.
    - If path targets /api/ or raw assets, return standard 404 JSON/error.
    - If path is an unknown frontend route, serve the React SPA with a genuine HTTP 404 status code,
      allowing the frontend router to render the custom ZeroDay 404 page.
    """
    if ".." in full_path or full_path.startswith(".") or full_path.startswith("/") or full_path.startswith("\\"):
        raise HTTPException(status_code=404, detail="Not Found")

    # Protect API namespace, OpenAPI spec, and raw static assets
    if (
        full_path.startswith("api/")
        or full_path == "api"
        or full_path.startswith("static/")
        or full_path.startswith("assets/")
        or full_path.startswith("openapi.json")
    ):
        raise HTTPException(status_code=404, detail="Not Found")

    # Serve static assets from root if present (e.g. favicon.ico, favicon.svg, site.webmanifest, app icons)
    for base in ["static_dist", "static"]:
        base_path = Path(base).resolve()
        cand = (base_path / full_path).resolve()
        if cand.is_file() and not cand.name.startswith(".") and cand.is_relative_to(base_path):
            return FileResponse(cand)

    return _serve_spa_index(status_code=404)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
