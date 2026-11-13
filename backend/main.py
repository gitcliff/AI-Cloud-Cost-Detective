import asyncio
import logging
import os
import re
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from ai_analyzer import analyze_aws_resources, build_deterministic_result
from auth import create_token, decode_token_raw, get_current_user, hash_password, verify_password
from aws_scanner import get_regions, scan_region
from cost_explorer import fetch_cost_data, merge_costs_with_resources
from db import (
    create_pending_analysis,
    create_pool,
    create_tables,
    create_user,
    get_analysis_by_id,
    get_analysis_owner,
    get_history,
    get_user_by_email,
    update_analysis,
)
from governance import service as governance_service
from governance import store as governance_store
from governance.api import router as governance_router
from governance.rules import RULES as GOVERNANCE_RULES
from models import (
    AnalyzeRequest,
    AnalyzeResponse,
    AuthResponse,
    LoginRequest,
    RegionInfo,
    SignupRequest,
)
from pricing_engine import detect_and_price_issues

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

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
    await governance_store.sync_rules(app.state.db_pool, GOVERNANCE_RULES)
    interrupted = await governance_store.fail_interrupted_scans(app.state.db_pool)
    if interrupted:
        logger.warning("Marked %d governance scan(s) interrupted by restart as failed", interrupted)
    logger.info("Database initialized")
    yield
    await app.state.db_pool.close()
    logger.info("Database pool closed")


app = FastAPI(title="AI Cloud Cost Detective for AWS", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("CORS_ORIGIN", "http://localhost:5173")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(governance_router)


# ── Auth endpoints ──────────────────────────────────────────────────────────


@app.post("/api/auth/signup", response_model=AuthResponse)
async def signup(request: SignupRequest):
    pool = app.state.db_pool

    # Every user of a deployment scans the same server-side AWS account, so shared
    # deployments should turn open sign-up off.
    if os.getenv("ALLOW_SIGNUP", "true").strip().lower() == "false":
        raise HTTPException(status_code=403, detail="Sign-up is disabled on this deployment")

    if not EMAIL_RE.match(request.email):
        raise HTTPException(status_code=400, detail="Invalid email address")

    if len(request.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    hashed = await hash_password(request.password)

    try:
        user_id = await create_user(pool, request.email, hashed)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e

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


async def _run_analysis(
    analysis_id: int,
    region: str,
    include_cost_data: bool = True,
    user_id: int | None = None,
    include_governance: bool = False,
) -> None:
    """Background task: scan AWS, run AI analysis, store results.

    The governance scan runs concurrently and independently: its failure is
    recorded on the governance scan and never fails the cost analysis.
    """
    pool = app.state.db_pool
    governance_task = None
    if include_governance and user_id is not None:
        governance_task = governance_service.spawn(
            governance_service.run_governance_stage(pool, user_id, region, analysis_id)
        )

    try:
        await _push_progress(analysis_id, "Connecting to AWS region...", 5)

        # Scan AWS resources and fetch cost data in parallel
        await _push_progress(analysis_id, "Scanning AWS resources...", 15)
        loop = asyncio.get_event_loop()
        scan_future = loop.run_in_executor(None, scan_region, region)
        if include_cost_data:
            cost_future = loop.run_in_executor(None, fetch_cost_data, region)

        resources = await scan_future
        await _push_progress(analysis_id, "Fetching cost data from AWS...", 50)
        cost_data = (await cost_future) if include_cost_data else {"available": False}

        # Merge cost data into resources if available
        if cost_data.get("available"):
            await _push_progress(analysis_id, "Merging cost data...", 55)
            resources = merge_costs_with_resources(resources, cost_data)

        await _push_progress(analysis_id, "Scanning complete", 60)

        # Run deterministic pricing engine to pre-calculate savings
        await _push_progress(analysis_id, "Calculating savings from pricing data...", 63)
        precalculated_issues = await loop.run_in_executor(
            None,
            detect_and_price_issues,
            resources,
            region,
        )

        # Send resources + pre-calculated issues to LLM for explanation
        await _push_progress(analysis_id, "Analyzing costs with AI...", 70)
        try:
            result = await analyze_aws_resources(region, resources, cost_data, precalculated_issues)
        except Exception as ai_err:
            # The LLM only explains; deterministic findings must survive its failure.
            logger.warning("AI analysis unavailable for analysis %d: %s", analysis_id, ai_err)
            await _push_progress(analysis_id, "AI unavailable, saving deterministic results...", 80)
            result = build_deterministic_result(region, resources, cost_data, precalculated_issues, str(ai_err))

        if governance_task is not None:
            await _push_progress(analysis_id, "Finishing governance evaluation...", 85)
            result["governance"] = await governance_task

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
            {
                "resources_scanned": 0,
                "issues_found": 0,
                "estimated_total_savings": "$0/month",
                "summary": f"Analysis failed: {e}",
                "issues": [],
            },
            status="failed",
        )
        await _push_progress(analysis_id, f"Analysis failed: {e}", -1)

    finally:
        if governance_task is not None and not governance_task.done():
            await governance_task  # never raises; let it record its own outcome
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

    # Launch analysis in the background so the endpoint returns immediately.
    # spawn() keeps a reference so the task can't be garbage-collected mid-run.
    governance_service.spawn(
        _run_analysis(
            analysis_id,
            request.region,
            request.include_cost_data,
            user_id=user_id,
            include_governance=request.include_governance,
        )
    )

    return AnalyzeResponse(analysis_id=analysis_id)


@app.websocket("/ws/progress/{analysis_id}")
async def websocket_progress(
    websocket: WebSocket,
    analysis_id: int,
    token: str = Query(default=""),
):
    # Validate JWT before accepting the WebSocket connection
    if not token:
        await websocket.close(code=4001, reason="Missing token")
        return

    user_id = decode_token_raw(token)
    if user_id is None:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    await websocket.accept()

    # Only the analysis owner may follow its progress. Answer exactly as for a
    # missing analysis so other users' analysis IDs aren't revealed.
    owner = await get_analysis_owner(app.state.db_pool, analysis_id)
    queue = progress_queues.get(analysis_id) if owner == user_id else None
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
    result = await get_analysis_by_id(pool, analysis_id, user_id=user_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result
