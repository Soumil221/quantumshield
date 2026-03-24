# main.py — Quantum Shield API entry point
#
# Run with:
#   uvicorn main:app --reload --host 0.0.0.0 --port 8000
#
# Required env vars:
#   MONGO_URI      mongodb://localhost:27017        (or Atlas connection string)
#   MONGO_DB_NAME  quantumshield                   (optional, default shown)

import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from functools import partial

from fastapi import FastAPI, Request, status  # type: ignore
from fastapi.exceptions import RequestValidationError  # type: ignore
from fastapi.responses import JSONResponse  # type: ignore

from db.mongo import init_mongo, close_mongo, get_cbom_collection
from models import (
    CBOMResponse,
    DomainRequest,
    ErrorDetail,
    AssetAnalysis,
    FullAnalysisResponse,
    RecommendationBatchResponse,
    RecommendationReportSchema,
    RecommendationSchema,
    RiskAnalysisBatchResponse,
    RiskAnalysisSchema,
    RiskFindingSchema,
    ScanRequest,
    ScanResponse,
    DiscoverResponse,
    TLSScanResponse,
)
from services.asset_discovery import discover_assets
from services.tls_scanner import scan_tls_assets
from services.cbom_generator import process_and_store_cbom
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

# ── Logging ──────────────────────────────────────────────────────────────── #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────── #
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Quantum Shield API starting up …")
    init_mongo()          # connect to MongoDB, verify indexes
    yield
    close_mongo()         # gracefully close the connection pool
    logger.info("Quantum Shield API shutting down …")


# ── App ───────────────────────────────────────────────────────────────────── #
app = FastAPI(
    title="Quantum Shield API",
    description=(
        "Modular cybersecurity scanning platform.\n\n"
        "**Phase 1** — Input validation & API scaffolding.\n"
        "**Phase 2** — Asset discovery (Subfinder → DNS → Nmap).\n"
        "**Phase 3** — TLS & cryptography scanning.\n"
        "**Phase 4** — CBOM generation and PostgreSQL persistence.\n"
        "**Phase 5** — HTTP security header analysis.\n"
    ),
    version="0.5.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Risk & Recommendation endpoints (previously in routes_risk.py)
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


def _fetch_cbom_records(domain: str) -> list[dict]:
    """Fetch all CBOM records whose asset contains the given domain."""
    col = get_cbom_collection()
    cursor = col.find(
        {"asset": {"$regex": domain, "$options": "i"}},
        {"_id": 0},
    )
    return list(cursor)


@app.post(
    "/risk",
    response_model=RiskAnalysisBatchResponse,
    responses={400: {"model": ErrorDetail}, 500: {"model": ErrorDetail}},
    summary="Quantum Risk Analyzer — score all CBOM assets for a domain",
)
async def analyze_risk_endpoint(request: DomainRequest):
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


@app.post(
    "/recommend",
    response_model=RecommendationBatchResponse,
    responses={400: {"model": ErrorDetail}, 500: {"model": ErrorDetail}},
    summary="Recommendation Engine — generate remediation advice for a domain",
)
async def recommendations_endpoint(request: DomainRequest):
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


@app.post(
    "/analyze",
    response_model=FullAnalysisResponse,
    responses={400: {"model": ErrorDetail}, 500: {"model": ErrorDetail}},
    summary="Full analysis — risk scores + recommendations in a single call",
)
async def full_analysis_endpoint(request: DomainRequest):
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


# ── Exception handlers ────────────────────────────────────────────────────── #
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    messages = "; ".join(
        f"{' → '.join(str(loc) for loc in err['loc'])}: {err['msg']}"
        for err in exc.errors()
        if err.get("loc")
    ) or str(exc)
    logger.warning("Validation error on %s: %s", request.url.path, messages)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ErrorDetail(message=messages).model_dump(),
    )


@app.exception_handler(Exception)
async def generic_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    logger.exception("Unhandled exception on %s", request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorDetail(message="An internal server error occurred.").model_dump(),
    )


# ── Helper ────────────────────────────────────────────────────────────────── #
async def _run(fn, *args):
    """Run a blocking function in the default thread pool executor."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, partial(fn, *args))

# ── Routes ────────────────────────────────────────────────────────────────── #

@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


# ── Phase 2 ───────────────────────────────────────────────────────────────── #
@app.post(
    "/discover",
    response_model=DiscoverResponse,
    tags=["Phase 2 — Asset Discovery"],
    summary="Discover subdomains, IPs, and open ports for a domain",
    responses={422: {"model": ErrorDetail}, 500: {"model": ErrorDetail}},
)
async def discover_domain(payload: DomainRequest) -> DiscoverResponse:
    """Subfinder → DNS → Nmap. ⚠️ Long-running."""
    logger.info("POST /discover — domain: %s", payload.domain)
    assets = await _run(discover_assets, payload.domain)
    return DiscoverResponse(
        domain=payload.domain,
        status="success",
        total_assets=len(assets),
        assets=assets,
    )


# ── Phase 3 ───────────────────────────────────────────────────────────────── #
@app.post(
    "/scan-tls",
    response_model=TLSScanResponse,
    tags=["Phase 3 — TLS Scanner"],
    summary="Discover assets then perform full TLS scan (one call does it all)",
    responses={422: {"model": ErrorDetail}, 500: {"model": ErrorDetail}},
)
async def scan_tls(payload: DomainRequest) -> TLSScanResponse:
    """
    **All-in-one**: Subfinder → DNS → Nmap → TLS handshakes.
    Just supply a domain — asset discovery runs automatically.
    ⚠️ Long-running.
    """
    logger.info("POST /scan-tls — domain: %s", payload.domain)
    assets = await _run(discover_assets, payload.domain)

    if not assets:
        return TLSScanResponse(status="success",
            total_hosts_scanned=0, total_ports_scanned=0, total_warnings=0, results=[])

    asset_results = await _run(scan_tls_assets, assets)

    total_ports    = sum(len(r.scanned_ports) for r in asset_results)
    total_warnings = sum(sum(len(res.warnings) for res in r.results) for r in asset_results)

    logger.info("POST /scan-tls done — %d hosts, %d ports, %d warnings",
        len(asset_results), total_ports, total_warnings)

    return TLSScanResponse(
        status="success",
        total_hosts_scanned=len(asset_results),
        total_ports_scanned=total_ports,
        total_warnings=total_warnings,
        results=asset_results,
    )


# ── Phase 4 ───────────────────────────────────────────────────────────────── #
@app.post(
    "/cbom",
    response_model=CBOMResponse,
    tags=["Phase 4 — CBOM"],
    summary="Full CBOM pipeline — just supply a domain",
    responses={422: {"model": ErrorDetail}, 500: {"model": ErrorDetail}},
)
async def generate_cbom(payload: DomainRequest) -> CBOMResponse:
    """
    **All-in-one** Cryptographic Bill of Materials generator.

    Internally runs the full chain:
    **Subfinder → DNS → Nmap → TLS handshakes → CBOM → MongoDB**

    Just supply a domain — every step runs automatically.

    - Discovers all subdomains and open ports
    - Performs real TLS handshakes on every TLS-capable port
    - Parses each cipher suite into its cryptographic components
    - Normalises TLS version strings
    - Upserts results into `cbom_inventory` in MongoDB

    ⚠️ Long-running — budget several minutes for large domains.
    """
    logger.info("POST /cbom — domain: %s", payload.domain)

    # Step 1: Asset discovery
    assets = await _run(discover_assets, payload.domain)
    if not assets:
        logger.warning("POST /cbom — no assets found for %s", payload.domain)
        return CBOMResponse(status="success", total_records=0, records=[])

    logger.info("POST /cbom — %d assets found, running TLS scan …", len(assets))

    # Step 2: TLS scanning — returns list[TLSAssetResult]
    asset_results = await _run(scan_tls_assets, assets)

    # Step 3: Flatten TLSAssetResult → list[TLSScanResult] for CBOM ingestion
    tls_results = [res for ar in asset_results for res in ar.results]

    if not tls_results:
        logger.warning("POST /cbom — no successful TLS results for %s", payload.domain)
        return CBOMResponse(status="success", total_records=0, records=[])

    logger.info("POST /cbom — %d TLS results, generating CBOM …", len(tls_results))

    # Step 4: Transform → deduplicate → persist to MongoDB
    records = await _run(process_and_store_cbom, tls_results)

    logger.info("POST /cbom done — %d records stored for %s", len(records), payload.domain)
    return CBOMResponse(status="success", total_records=len(records), records=records)

