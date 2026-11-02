import asyncio
import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware

from ai_analyzer import analyze_aws_resources
from auth import get_current_user, hash_password, verify_password, create_token
from aws_scanner import get_regions, scan_region
from db import (
    create_pool, create_tables, create_pending_analysis, update_analysis,
    get_history, get_analysis_by_id, get_user_by_email, create_user,
)
from models import (
    AnalyzeRequest, AnalyzeResponse, AuthResponse, LoginRequest,
    RegionInfo, SignupRequest,
)

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory queues for WebSocket progress messages per analysis_id
progress_queues: dict[int, asyncio.Queue] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create DB pool + tables. Shutdown: close pool."""
    app.state.db_pool = await create_pool()
    await create_tables(app.state.db_pool)
    logger.info("Database initialized")
    yield
    await app.state.db_pool.close()
    logger.info("Database pool closed")


app = FastAPI(title="AI Cloud Cost Detective", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("CORS_ORIGIN", "http://localhost:5173")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth endpoints ──────────────────────────────────────────────────────────


@app.post("/api/auth/signup", response_model=AuthResponse)
async def signup(request: SignupRequest):
    pool = app.state.db_pool

    if len(request.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    hashed = await hash_password(request.password)

    try:
        user_id = await create_user(pool, request.email, hashed)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    token = create_token(user_id)
    return AuthResponse(token=token, user_id=user_id)


@app.post("/api/auth/login", response_model=AuthResponse)
async def login(request: LoginRequest):
    pool = app.state.db_pool

    user = await get_user_by_email(pool, request.email)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    valid = await verify_password(request.password, user["password_hash"])
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token(user["id"])
    return AuthResponse(token=token, user_id=user["id"])


# ── Protected endpoints ─────────────────────────────────────────────────────


async def _push_progress(analysis_id: int, step: str, percent: int) -> None:
    """Push a progress message to the WebSocket queue for this analysis."""
    queue = progress_queues.get(analysis_id)
    if queue:
        await queue.put({"step": step, "percent": percent})


async def _run_analysis(analysis_id: int, region: str) -> None:
    """Background task: scan AWS, run AI analysis, store results."""
    pool = app.state.db_pool

    try:
        await _push_progress(analysis_id, "Connecting to AWS region...", 5)

        # Step 3 — Scan AWS resources via boto3 (sync, run in executor)
        await _push_progress(analysis_id, "Scanning EC2 instances...", 15)
        loop = asyncio.get_event_loop()
        resources = await loop.run_in_executor(None, scan_region, region)

        await _push_progress(analysis_id, "Scanning complete", 60)

        # Step 5 — Send resources to OpenAI for cost analysis
        await _push_progress(analysis_id, "Analyzing costs with AI...", 70)
        result = await analyze_aws_resources(region, resources)

        # Step 6 — Store results in PostgreSQL
        await _push_progress(analysis_id, "Storing results...", 90)
        await update_analysis(pool, analysis_id, result, status="completed")

        result["analysis_id"] = analysis_id
        await _push_progress(analysis_id, "Analysis complete", 100)

    except Exception as e:
        logger.error("Analysis %d failed: %s", analysis_id, e)
        await update_analysis(
            pool,
            analysis_id,
            {"resources_scanned": 0, "issues_found": 0, "estimated_total_savings": "$0/month",
             "summary": f"Analysis failed: {e}", "issues": []},
            status="failed",
        )
        await _push_progress(analysis_id, f"Analysis failed: {e}", -1)

    finally:
        # Clean up the queue after a short delay so the client can read the final message
        await asyncio.sleep(2)
        progress_queues.pop(analysis_id, None)


@app.get("/api/regions", response_model=list[RegionInfo])
async def list_regions(user_id: int = Depends(get_current_user)):
    return get_regions()


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest, user_id: int = Depends(get_current_user)):
    valid_ids = {r["id"] for r in get_regions()}
    if request.region not in valid_ids:
        raise HTTPException(status_code=400, detail=f"Invalid region: {request.region}")

    pool = app.state.db_pool

    # Create a pending analysis row so we have an ID for WebSocket tracking
    analysis_id = await create_pending_analysis(pool, user_id=user_id, region=request.region)

    # Set up a progress queue before launching the background task
    progress_queues[analysis_id] = asyncio.Queue()

    # Launch analysis in the background so the endpoint returns immediately
    asyncio.create_task(_run_analysis(analysis_id, request.region))

    return AnalyzeResponse(analysis_id=analysis_id)


@app.websocket("/ws/progress/{analysis_id}")
async def websocket_progress(websocket: WebSocket, analysis_id: int):
    await websocket.accept()

    queue = progress_queues.get(analysis_id)
    if not queue:
        await websocket.send_json({"step": "No active analysis found", "percent": -1})
        await websocket.close()
        return

    try:
        while True:
            message = await queue.get()
            await websocket.send_json(message)
            if message.get("percent") in (100, -1):
                break
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected for analysis %d", analysis_id)
    finally:
        await websocket.close()


@app.get("/api/history")
async def list_history(user_id: int = Depends(get_current_user)):
    pool = app.state.db_pool
    return await get_history(pool, user_id=user_id)


@app.get("/api/history/{analysis_id}")
async def get_history_detail(analysis_id: int, user_id: int = Depends(get_current_user)):
    pool = app.state.db_pool
    result = await get_analysis_by_id(pool, analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result
