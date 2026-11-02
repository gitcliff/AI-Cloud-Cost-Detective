import asyncio
import logging
import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from ai_analyzer import analyze_aws_resources
from aws_scanner import get_regions, scan_region
from models import AnalyzeRequest, RegionInfo

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AI Cloud Cost Detective", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("CORS_ORIGIN", "http://localhost:5173")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/regions", response_model=list[RegionInfo])
async def list_regions():
    return get_regions()


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest):
    valid_ids = {r["id"] for r in get_regions()}
    if request.region not in valid_ids:
        raise HTTPException(status_code=400, detail=f"Invalid region: {request.region}")

    # Step ③ — Scan AWS resources via boto3
    try:
        loop = asyncio.get_event_loop()
        resources = await loop.run_in_executor(None, scan_region, request.region)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Step ⑤ — Send resources to OpenAI for cost analysis
    try:
        analysis = await analyze_aws_resources(request.region, resources)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    return analysis
