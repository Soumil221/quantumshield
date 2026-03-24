"""
New FastAPI routes to add to main.py for Quantum Risk Analyzer and
Recommendation Engine.

HOW TO INTEGRATE:
  In main.py, add:

    from routes_risk import router as risk_router
    app.include_router(risk_router)

Or copy the routes directly into main.py.
"""

from __future__ import annotations

import asyncio
from functools import partial
from typing import Any

try:
    from fastapi import APIRouter
except Exception:  # pragma: no cover - fallback for environments without FastAPI
    class APIRouter:  # type: ignore
        def __init__(self, *args, **kwargs):
            pass

        def post(self, path: str, **kwargs):
            def decorator(fn):
                return fn

            return decorator

        def get(self, path: str, **kwargs):
            def decorator(fn):
                return fn

            return decorator

from db.mongo import get_cbom_collection
from models_risk import (
    AssetAnalysis,
    FullAnalysisResponse,
    RecommendationBatchResponse,
    RecommendationReportSchema,
    RecommendationSchema,
    RiskAnalysisBatchResponse,
    RiskAnalysisSchema,
    RiskFindingSchema,
)
from services.recommendation_engine import (
    RecommendationReport,
    generate_recommendations,
    generate_recommendations_batch,
)
from services.risk_analyzer import (
    RiskAnalysisResult,
    analyze_risk,
    analyze_risk_batch,
)

# Shared DomainRequest import — adjust if your models.py name differs
from models import DomainRequest, ErrorDetail

router = APIRouter(tags=["Risk & Recommendations"])


# ---------------------------------------------------------------------------
# Executor helper (same pattern as the rest of the project)
# ---------------------------------------------------------------------------

async def _run(func, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, partial(func, *args, **kwargs))


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _risk_result_to_schema(r: RiskAnalysisResult) -> RiskAnalysisSchema:
    return RiskAnalysisSchema(
        asset=r.asset,
        port=r.port,
        risk_score=r.risk_score,
        risk_level=r.risk_level,
        risk_score_display=r.risk_score_display,
        findings=[
            RiskFindingSchema(
                category=f.category,
                detail=f.detail,
                score_contribution=f.score_contribution,
                severity=f.severity,
            )
            for f in r.findings
        ],
        is_quantum_safe=r.is_quantum_safe,
        quantum_safe_reason=r.quantum_safe_reason,
    )


def _rec_report_to_schema(rp: RecommendationReport) -> RecommendationReportSchema:
    return RecommendationReportSchema(
        asset=rp.asset,
        port=rp.port,
        risk_score=rp.risk_score,
        risk_level=rp.risk_level,
        is_quantum_safe=rp.is_quantum_safe,
        recommendations=[
            RecommendationSchema(
                priority=rec.priority,
                category=rec.category,
                title=rec.title,
                detail=rec.detail,
                action=rec.action,
                reference=rec.reference,
            )
            for rec in rp.recommendations
        ],
        summary=rp.summary,
    )


def _count_levels(results: list[RiskAnalysisResult]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0}
    for r in results:
        counts[r.risk_level.lower()] = counts.get(r.risk_level.lower(), 0) + 1
    return counts


# ---------------------------------------------------------------------------
# MongoDB fetch helper (blocking — runs in executor)
# ---------------------------------------------------------------------------

def _fetch_cbom_records(domain: str) -> list[dict]:
    """Fetch all CBOM records whose asset contains the given domain."""
    col = get_cbom_collection()
    cursor = col.find(
        {"asset": {"$regex": domain, "$options": "i"}},
        {"_id": 0},
    )
    return list(cursor)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post(
    "/risk",
    response_model=RiskAnalysisBatchResponse,
    responses={400: {"model": ErrorDetail}, 500: {"model": ErrorDetail}},
    summary="Quantum Risk Analyzer — score all CBOM assets for a domain",
)
async def analyze_risk_endpoint(request: DomainRequest):
    """
    Fetch all CBOM inventory records for *domain* from MongoDB and compute
    a cryptographic risk score (0–10) for each asset:port combination.

    **Requires** the `/cbom` endpoint to have been run first so records exist
    in the database.
    """
    try:
        records = await _run(_fetch_cbom_records, request.domain)
    except Exception as exc:
        return ErrorDetail(status="error", message=f"Database error: {exc}")

    if not records:
        return ErrorDetail(
            status="error",
            message=(
                f"No CBOM records found for domain '{request.domain}'. "
                "Run /cbom first to populate the inventory."
            ),
        )

    # analyse_risk_batch is CPU-bound; run in executor
    risk_results: list[RiskAnalysisResult] = await _run(analyze_risk_batch, records)

    counts = _count_levels(risk_results)

    return RiskAnalysisBatchResponse(
        status="success",
        domain=request.domain,
        total_assets_analyzed=len(risk_results),
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        safe_count=counts["safe"],
        results=[_risk_result_to_schema(r) for r in risk_results],
    )


@router.post(
    "/recommend",
    response_model=RecommendationBatchResponse,
    responses={400: {"model": ErrorDetail}, 500: {"model": ErrorDetail}},
    summary="Recommendation Engine — generate remediation advice for a domain",
)
async def recommendations_endpoint(request: DomainRequest):
    """
    Fetch CBOM records for *domain*, run the risk analyzer, then generate
    prioritised, actionable remediation recommendations for each asset:port.

    **Requires** the `/cbom` endpoint to have been run first.
    """
    try:
        records = await _run(_fetch_cbom_records, request.domain)
    except Exception as exc:
        return ErrorDetail(status="error", message=f"Database error: {exc}")

    if not records:
        return ErrorDetail(
            status="error",
            message=(
                f"No CBOM records found for domain '{request.domain}'. "
                "Run /cbom first to populate the inventory."
            ),
        )

    risk_results: list[RiskAnalysisResult] = await _run(analyze_risk_batch, records)

    reports = await _run(
        generate_recommendations_batch, risk_results, records
    )

    return RecommendationBatchResponse(
        status="success",
        domain=request.domain,
        total_assets=len(reports),
        reports=[_rec_report_to_schema(rp) for rp in reports],
    )


@router.post(
    "/analyze",
    response_model=FullAnalysisResponse,
    responses={400: {"model": ErrorDetail}, 500: {"model": ErrorDetail}},
    summary="Full analysis — risk scores + recommendations in a single call",
)
async def full_analysis_endpoint(request: DomainRequest):
    """
    Combined endpoint: fetch CBOM → risk analysis → recommendations.

    Returns a unified response with risk scores and remediation advice
    for every asset:port in the domain's CBOM inventory.
    """
    try:
        records = await _run(_fetch_cbom_records, request.domain)
    except Exception as exc:
        return ErrorDetail(status="error", message=f"Database error: {exc}")

    if not records:
        return ErrorDetail(
            status="error",
            message=(
                f"No CBOM records found for domain '{request.domain}'. "
                "Run /cbom first to populate the inventory."
            ),
        )

    risk_results: list[RiskAnalysisResult] = await _run(analyze_risk_batch, records)

    reports = await _run(
        generate_recommendations_batch, risk_results, records
    )

    counts = _count_levels(risk_results)
    quantum_safe_count = sum(1 for r in risk_results if r.is_quantum_safe)

    # Zip risk + recommendations into combined AssetAnalysis objects
    analyses = [
        AssetAnalysis(
            risk=_risk_result_to_schema(risk),
            recommendations=_rec_report_to_schema(report),
        )
        for risk, report in zip(risk_results, reports)
    ]

    return FullAnalysisResponse(
        status="success",
        domain=request.domain,
        total_assets=len(analyses),
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        safe_count=counts["safe"],
        quantum_safe_count=quantum_safe_count,
        analyses=analyses,
    )