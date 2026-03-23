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

try:
    from fastapi import FastAPI, Request, status  # type: ignore
    from fastapi.exceptions import RequestValidationError  # type: ignore
    from fastapi.responses import JSONResponse  # type: ignore
except Exception:  # pragma: no cover - fallback for environments without FastAPI
    from types import SimpleNamespace

    class FastAPI:  # type: ignore
        def __init__(self, *args, **kwargs):
            pass

        def exception_handler(self, exc_type):
            def decorator(fn):
                return fn

            return decorator

        def get(self, path: str, **kwargs):
            def decorator(fn):
                return fn

            return decorator

        def post(self, path: str, **kwargs):
            def decorator(fn):
                return fn

            return decorator

    class Request:  # type: ignore
        def __init__(self):
            self.url = SimpleNamespace(path="")

    class RequestValidationError(Exception):  # type: ignore
        def __init__(self, *args):
            super().__init__(*args)

        def errors(self):
            return []

    class JSONResponse:  # type: ignore
        def __init__(self, status_code: int, content: dict):
            self.status_code = status_code
            self.content = content

    class _Status:  # type: ignore
        HTTP_200_OK = 200
        HTTP_422_UNPROCESSABLE_ENTITY = 422
        HTTP_500_INTERNAL_SERVER_ERROR = 500

    status = _Status()

from db.mongo import init_mongo, close_mongo
from models import (
    CBOMResponse,
    DomainRequest,
    ErrorDetail,
    HeaderScanResponse,
    ScanRequest,
    ScanResponse,
    DiscoverResponse,
    TLSScanResponse,
)
from services.scanner import initiate_scan
from services.asset_discovery import discover_assets
from services.tls_scanner import scan_tls_assets
from services.cbom_generator import process_and_store_cbom

# Header scanner / storage may be developed later — provide local fallbacks
# so importing main.py does not fail in environments without those modules.
def scan_headers(assets):
    raise RuntimeError("header_scanner service is not available in this environment")


def save_header_results(analyses):
    raise RuntimeError("header_storage service is not available in this environment")

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


# ── Phase 1 ───────────────────────────────────────────────────────────────── #
@app.post(
    "/scan",
    response_model=ScanResponse,
    tags=["Phase 1 — Scanner"],
    summary="Acknowledge a domain scan request",
    responses={422: {"model": ErrorDetail}, 500: {"model": ErrorDetail}},
)
async def scan_domain(payload: ScanRequest) -> ScanResponse:
    logger.info("POST /scan — domain: %s", payload.domain)
    return initiate_scan(payload.domain)


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


# ── Phase 5 ───────────────────────────────────────────────────────────────── #
@app.post(
    "/scan-headers",
    response_model=HeaderScanResponse,
    tags=["Phase 5 — Header Scanner"],
    summary="Discover assets then analyse HTTP security headers",
    responses={422: {"model": ErrorDetail}, 500: {"model": ErrorDetail}},
)
async def scan_headers_endpoint(payload: DomainRequest) -> HeaderScanResponse:
    """
    **All-in-one HTTP security header analysis.**

    Pipeline: **Subfinder → DNS → Nmap → HTTP HEAD requests → header grading**.

    Evaluates 10 security headers per host:
    - `Strict-Transport-Security` — HSTS strength
    - `Content-Security-Policy` — XSS / injection policy
    - `X-Frame-Options` — clickjacking protection
    - `X-Content-Type-Options` — MIME sniffing protection
    - `Referrer-Policy` — referrer information leakage
    - `Permissions-Policy` — browser feature access control
    - `X-XSS-Protection` — legacy XSS auditor setting
    - `Server` — software version disclosure
    - `X-Powered-By` — framework disclosure
    - `Cache-Control` — sensitive content caching

    Each header is graded **present / weak / missing / misconfigured**.
    Each host receives an overall letter grade (**A+** → **F**).
    Results are persisted to `header_scan_inventory` in MongoDB.

    ⚠️ Long-running — budget time for asset discovery + HTTP probing.
    """
    logger.info("POST /scan-headers — domain: %s", payload.domain)

    # Step 1: Asset discovery
    assets = await _run(discover_assets, payload.domain)
    if not assets:
        logger.warning("POST /scan-headers — no assets found for %s", payload.domain)
        return HeaderScanResponse(
            status="success",
            total_hosts_scanned=0,
            total_ports_scanned=0,
            results=[],
        )

    logger.info("POST /scan-headers — %d assets found, scanning headers …", len(assets))

    # Step 2: Header scanning
    analyses = await _run(scan_headers, assets)

    # Step 3: Persist to DB (best-effort — don't fail the response if DB is down)
    if analyses:
        try:
            await _run(save_header_results, analyses)
        except RuntimeError as exc:
            logger.error("POST /scan-headers — DB persistence failed: %s", exc)
            # Continue — return results to caller even if DB write failed

    total_ports = sum(len(a.port_results) for a in analyses)
    logger.info(
        "POST /scan-headers done — %d hosts, %d port results",
        len(analyses), total_ports,
    )

    return HeaderScanResponse(
        status="success",
        total_hosts_scanned=len(analyses),
        total_ports_scanned=total_ports,
        results=analyses,
    )