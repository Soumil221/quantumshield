# db/mongo.py
#
# MongoDB connection layer for Quantum Shield.
#
# Driven entirely by environment variables — no credentials ever hardcoded.
#
# Required:
#   MONGO_URI      mongodb://localhost:27017          (or Atlas URI)
#
# Optional:
#   MONGO_DB_NAME  quantumshield                      (default)
#
# Design:
#   - Single MongoClient instance (thread-safe, connection-pooled internally)
#   - Lazy initialisation: importing this module does NOT open a socket
#   - init_mongo() is called once from the FastAPI lifespan handler
#   - get_cbom_collection() / get_header_collection() give typed access to
#     specific collections without callers knowing the DB name
#   - Indexes are created with create_index(…, background=True) so startup
#     does not block if the collection already has data

from dotenv import load_dotenv
import logging
import os
from typing import Any, Optional
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI", "").strip()
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "quantumshield").strip()
try:
    from pymongo import ASCENDING, MongoClient  # type: ignore
    from pymongo.collection import Collection  # type: ignore
    from pymongo.database import Database  # type: ignore
except Exception:  # pragma: no cover - environment without pymongo
    # Fallbacks for static analysis and import-time resilience. init_mongo
    # will raise a clear error if pymongo is not installed when a DB
    # connection is attempted.
    ASCENDING = 1  # type: ignore
    MongoClient = None  # type: ignore
    Collection = Any  # type: ignore
    Database = Any  # type: ignore

logger = logging.getLogger(__name__)

# ── Module-level singletons (initialised lazily) ──────────────────────────── #

_client: Optional[Any] = None
_db: Optional[Any] = None


# ── Configuration helpers ─────────────────────────────────────────────────── #

def _get_mongo_uri() -> str:
    uri = os.getenv("MONGO_URI", "").strip()
    if not uri:
        raise RuntimeError(
            "MONGO_URI environment variable is not set.\n"
            "Examples:\n"
            "  Local:  mongodb://localhost:27017\n"
            "  Atlas:  mongodb+srv://user:pass@cluster.mongodb.net\n"
            "  Auth:   mongodb://user:pass@host:27017/dbname?authSource=admin"
        )
    return uri


def _get_db_name() -> str:
    return os.getenv("MONGO_DB_NAME", "quantumshield").strip()


def _redact_uri(uri: str) -> str:
    """Strip password from URI for safe logging."""
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(uri)
        if parsed.password:
            netloc = parsed.netloc.replace(f":{parsed.password}@", ":***@")
            return urlunparse(parsed._replace(netloc=netloc))
    except Exception:  # noqa: BLE001
        pass
    return uri


# ── Initialisation ────────────────────────────────────────────────────────── #

def init_mongo() -> None:
    """
    Connect to MongoDB, select the database, and ensure all indexes exist.

    Call this exactly once from the FastAPI lifespan handler.
    Safe to call multiple times — subsequent calls are no-ops.

    Raises:
        RuntimeError: If MONGO_URI is not set or the server is unreachable.
    """
    global _client, _db

    if (_client is not None):
        return  # already initialised

    if MongoClient is None:
        raise RuntimeError("pymongo is not installed in this environment — cannot connect to MongoDB.")

    uri = _get_mongo_uri()
    db_name = _get_db_name()

    logger.info("[mongo] Connecting to: %s / db=%s", _redact_uri(uri), db_name)

    _client = MongoClient(
        uri,
        serverSelectionTimeoutMS=5_000,   # fail fast on startup
        connectTimeoutMS=5_000,
        socketTimeoutMS=10_000,
        maxPoolSize=20,
        retryWrites=True,
    )

    # Help static analyzers: ensure _client is not None here.
    assert _client is not None

    # Smoke-test: ping the server before declaring success
    try:
        _client.admin.command("ping")
        logger.info("[mongo] Connection OK.")
    except Exception as exc:
        _client = None
        _db = None
        raise RuntimeError(f"MongoDB connection failed: {exc}") from exc

    _db = _client[db_name]

    # Ensure indexes (idempotent — MongoDB skips existing ones)
    _ensure_indexes()


def _ensure_indexes() -> None:
    """
    Create all required indexes in the background.

    Called once at startup.  background=True means existing data is not
    locked during index build — critical for non-empty collections.
    """
    assert _db is not None, "DB not initialised"

    # ── cbom_inventory ────────────────────────────────────────────────────── #
    cbom = _db["cbom_inventory"]

    # Primary deduplication index — unique per (asset, port)
    cbom.create_index(
        [("asset", ASCENDING), ("port", ASCENDING)],
        unique=True,
        name="uq_cbom_asset_port",
        background=True,
    )
    # Fast lookup by hostname
    cbom.create_index([("asset", ASCENDING)], name="ix_cbom_asset", background=True)
    # Filter / aggregate by TLS version
    cbom.create_index([("tls_version", ASCENDING)], name="ix_cbom_tls_version", background=True)
    # Time-range queries
    cbom.create_index([("scanned_at", ASCENDING)], name="ix_cbom_scanned_at", background=True)

    # ── header_scan_inventory ─────────────────────────────────────────────── #
    hdrs = _db["header_scan_inventory"]
    hdrs.create_index(
        [("host", ASCENDING), ("port", ASCENDING), ("header_name", ASCENDING)],
        unique=True,
        name="uq_header_host_port_name",
        background=True,
    )
    hdrs.create_index([("host", ASCENDING)], name="ix_header_host", background=True)
    hdrs.create_index([("overall_grade", ASCENDING)], name="ix_header_grade", background=True)
    hdrs.create_index([("scanned_at", ASCENDING)], name="ix_header_scanned_at", background=True)

    logger.info("[mongo] Indexes verified / created.")


# ── Collection accessors ──────────────────────────────────────────────────── #

def _require_db() -> Any:
    if _db is None:
        raise RuntimeError(
            "MongoDB not initialised — call init_mongo() before accessing collections."
        )
    return _db


def get_cbom_collection() -> Any:
    """Return the cbom_inventory collection handle."""
    return _require_db()["cbom_inventory"]


def get_header_collection() -> Any:
    """Return the header_scan_inventory collection handle."""
    return _require_db()["header_scan_inventory"]


def close_mongo() -> None:
    """
    Close the MongoDB client connection pool.
    Call this from the FastAPI lifespan shutdown handler.
    """
    global _client, _db
    if _client is not None:
        _client.close()
        logger.info("[mongo] Connection closed.")
        _client = None
        _db = None