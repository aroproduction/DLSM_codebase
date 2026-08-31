"""app.py — DLSM ML Classifier HTTP Service (FastAPI).

Matches the contract defined in ML_CLASSIFIER_API_CONTRACT.md.

Endpoints:
  POST /classify   — Classify a single prompt through the dual-stage pipeline
  GET  /health     — Service health check with model status

Usage:
  uvicorn app:app --host 127.0.0.1 --port 4000
"""

import os
import logging
from time import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from pipeline import Pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="DLSM ML Classifier Service",
    version=os.environ.get("MODEL_VERSION", "dlsm-ml-v1"),
    description="Dual-stage ML pipeline for DLSM: DistilBERT prefilter + Llama Guard 3 1B",
)


class ClassifyRequest(BaseModel):
    promptId: str = Field(..., min_length=1, description="Gateway-generated request ID")
    userId: str = Field(..., min_length=1, description="DLSM user identifier (Org1:user1)")
    orgId: str = Field(..., min_length=1, description="Organization ID (e.g. Org1)")
    prompt: str = Field(..., min_length=1, description="Raw prompt text to classify")
    promptHash: str = Field(
        ..., min_length=64, max_length=64,
        pattern="^[a-fA-F0-9]{64}$",
        description="SHA-256 hex hash of prompt",
    )
    conversationId: str = Field(
        "", description="Optional conversation/session identifier for multi-turn tracking"
    )
    history: list[str] = Field(
        default_factory=list,
        description="Optional prior turns (oldest first) for context-aware scoring",
    )


class ClassifyResponse(BaseModel):
    promptId: str
    userId: str
    orgId: str
    promptHash: str
    riskScore: float = Field(..., ge=0, le=1)
    binaryLabel: str
    dlsmClass: str
    attackFamily: str
    modelVersion: str
    timestamp: int


class HealthResponse(BaseModel):
    status: str
    version: str
    stage1_loaded: bool
    stage2_loaded: bool
    uptime_seconds: float


_pipeline: Pipeline = None
_start_time: float = 0.0


@app.on_event("startup")
def startup():
    global _pipeline, _start_time
    _start_time = time()
    logger.info("Starting DLSM ML Classifier Service")
    _pipeline = Pipeline(
        stage1_path=os.environ.get("STAGE1_MODEL_PATH"),
        stage2_model=os.environ.get("STAGE2_MODEL_ID"),
    )
    logger.info("Service ready — pipeline initialized")


@app.get("/health", response_model=HealthResponse)
def health():
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")
    return HealthResponse(
        status="ok",
        version=_pipeline._model_version,
        stage1_loaded=_pipeline._stage1 is not None,
        stage2_loaded=_pipeline._stage2 is not None,
        uptime_seconds=round(time() - _start_time, 2),
    )


@app.post("/classify", response_model=ClassifyResponse)
def classify(req: ClassifyRequest):
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    result = _pipeline.classify(
        prompt=req.prompt,
        prompt_id=req.promptId,
        user_id=req.userId,
        org_id=req.orgId,
        history=list(req.history) if req.history else None,
    )

    if result["promptHash"] != req.promptHash:
        logger.warning(
            "Hash mismatch: computed=%s received=%s",
            result["promptHash"], req.promptHash,
        )

    return result
