# services/cbom_generator.py
#
# CBOM (Cryptographic Bill of Materials) Generator — Phase 4 of Quantum Shield.
#
# Pipeline:
#   1. Receive TLSScanResult objects from the TLS scanner.
#   2. Normalise TLS version strings  (TLSv1.3 → TLS 1.3)
#   3. Parse cipher suite into components  (key_exchange, encryption, mac, cert algo)
#   4. Build CBOMRecord Pydantic objects.
#   5. Deduplicate on (asset, port) — last result for a pair wins.
#   6. Upsert into MongoDB cbom_inventory (replace_one with upsert=True).
#   7. Return the stored records to the API layer.
#
# Cipher format support:
#   TLS 1.3 IANA short:   TLS_AES_256_GCM_SHA384
#   TLS 1.2 IANA full:    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
#   OpenSSL dash-form:    ECDHE-RSA-AES256-GCM-SHA384

import logging
import re
from datetime import datetime, timezone
from typing import Optional

try:
    from pymongo import ReplaceOne  # type: ignore
    from pymongo.errors import BulkWriteError, PyMongoError  # type: ignore
except Exception:  # pragma: no cover - environment without pymongo
    ReplaceOne = None  # type: ignore
    BulkWriteError = Exception  # type: ignore
    PyMongoError = Exception  # type: ignore

from db.mongo import get_cbom_collection
from models import CBOMRecord, TLSScanResult

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════ #
# Section 1 — TLS Version Normalisation                                       #
# ═══════════════════════════════════════════════════════════════════════════ #

_TLS_VERSION_MAP: dict[str, str] = {
    "SSLv2":   "SSL 2.0",
    "SSLv3":   "SSL 3.0",
    "TLSv1":   "TLS 1.0",
    "TLSv1.0": "TLS 1.0",
    "TLSv1.1": "TLS 1.1",
    "TLSv1.2": "TLS 1.2",
    "TLSv1.3": "TLS 1.3",
}

_TLS_VERSION_RE = re.compile(r"TLS\s*v?(\d+(?:\.\d+)?)", re.IGNORECASE)


def normalize_tls_version(raw: Optional[str]) -> Optional[str]:
    """
    Convert any TLS/SSL version string into a clean human-readable label.

    Examples:
        "TLSv1.3"  -> "TLS 1.3"
        "TLSv1.2"  -> "TLS 1.2"
        "TLSv1"    -> "TLS 1.0"
        "SSLv3"    -> "SSL 3.0"
        None       -> None
    """
    if not raw:
        return None
    raw = raw.strip()

    if raw in _TLS_VERSION_MAP:
        return _TLS_VERSION_MAP[raw]

    m = _TLS_VERSION_RE.search(raw)
    if m:
        ver = m.group(1)
        if "." not in ver:
            ver += ".0"
        return f"TLS {ver}"

    logger.debug("[cbom] Unknown TLS version string %r — kept verbatim", raw)
    return raw


# ═══════════════════════════════════════════════════════════════════════════ #
# Section 2 — Cipher Suite Parser                                             #
# ═══════════════════════════════════════════════════════════════════════════ #

_KEY_EXCHANGE_TOKENS: frozenset[str] = frozenset([
    "ECDHE", "ECDH", "DHE", "DH", "RSA", "PSK", "SRP",
    "CECPQ2", "X25519", "X448",
])

_CERT_ALGO_TOKENS: frozenset[str] = frozenset([
    "RSA", "ECDSA", "DSS", "DSA", "ANON", "PSK", "ED25519", "ED448",
])

_ENCRYPTION_TOKENS: frozenset[str] = frozenset([
    "AES_256_GCM", "AES_128_GCM", "AES_256_CCM", "AES_128_CCM",
    "AES_256_CBC", "AES_128_CBC",
    "CHACHA20_POLY1305",
    "AES256", "AES128", "AES_256", "AES_128",
    "CHACHA20", "CAMELLIA256", "CAMELLIA128",
    "3DES", "DES", "RC4", "RC2",
    "ARIA256", "ARIA128",
])

_MAC_TOKENS: frozenset[str] = frozenset([
    "SHA384", "SHA256", "SHA224", "SHA", "MD5",
    "POLY1305", "SHA3_384", "SHA3_256",
])

_AEAD_MODES: frozenset[str] = frozenset(["GCM", "CCM", "POLY1305"])


class ParsedCipher:
    """Structured breakdown of a cipher suite string."""

    __slots__ = (
        "raw", "key_exchange", "certificate_algorithm",
        "encryption_algorithm", "mac_algorithm",
    )

    def __init__(
        self,
        raw: str,
        key_exchange: Optional[str] = None,
        certificate_algorithm: Optional[str] = None,
        encryption_algorithm: Optional[str] = None,
        mac_algorithm: Optional[str] = None,
    ) -> None:
        self.raw = raw
        self.key_exchange = key_exchange
        self.certificate_algorithm = certificate_algorithm
        self.encryption_algorithm = encryption_algorithm
        self.mac_algorithm = mac_algorithm

    def __repr__(self) -> str:
        return (
            f"ParsedCipher(kex={self.key_exchange!r}, "
            f"cert={self.certificate_algorithm!r}, "
            f"enc={self.encryption_algorithm!r}, "
            f"mac={self.mac_algorithm!r})"
        )


def _is_iana_tls13(name: str) -> bool:
    """TLS 1.3 IANA short form: TLS_AES_256_GCM_SHA384 (no _WITH_)."""
    return name.startswith("TLS_") and "_WITH_" not in name


def _is_iana_tls12(name: str) -> bool:
    """TLS 1.2 IANA full form: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384."""
    return name.startswith("TLS_") and "_WITH_" in name


def _is_openssl(name: str) -> bool:
    """OpenSSL dash-separated: ECDHE-RSA-AES256-GCM-SHA384."""
    return "-" in name and not name.startswith("TLS_")


def _parse_iana_tls13(name: str) -> ParsedCipher:
    """
    TLS 1.3 short IANA form: TLS_<ENC_PARTS>_<MAC>

    Examples:
        TLS_AES_256_GCM_SHA384       -> enc=AES_256_GCM, mac=SHA384
        TLS_CHACHA20_POLY1305_SHA256 -> enc=CHACHA20_POLY1305, mac=SHA256
    """
    body = name[4:]          # strip "TLS_"
    tokens = body.split("_")

    mac: Optional[str] = None
    enc_tokens: list[str] = list(tokens)

    # Peel rightmost MAC token
    for i in range(len(tokens) - 1, -1, -1):
        if tokens[i] in _MAC_TOKENS:
            mac = tokens[i]
            enc_tokens = tokens[:i]
            break

    # Try known compound tokens first
    enc_candidate = "_".join(enc_tokens)
    if enc_candidate in _ENCRYPTION_TOKENS:
        enc: Optional[str] = enc_candidate
    else:
        # Greedy: accumulate until AEAD mode terminator
        build: list[str] = []
        for t in enc_tokens:
            build.append(t)
            if t in _AEAD_MODES:
                break
        joined = "_".join(build)
        enc = joined if joined else (enc_candidate or None)

    return ParsedCipher(
        raw=name,
        key_exchange=None,
        certificate_algorithm=None,
        encryption_algorithm=enc or None,
        mac_algorithm=mac,
    )


def _parse_iana_tls12(name: str) -> ParsedCipher:
    """
    TLS 1.2 full IANA form: TLS_<KEX>_<CERT>_WITH_<ENC_PARTS>_<MAC>

    Example:
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            -> kex=ECDHE, cert=RSA, enc=AES_256_GCM, mac=SHA384
    """
    try:
        left, right = name.split("_WITH_", 1)
    except ValueError:
        logger.debug("[cbom] _WITH_ split failed for %r", name)
        return ParsedCipher(raw=name)

    # Left: TLS_<KEX>_<CERT>
    left_tokens = left.split("_")[1:]
    kex: Optional[str] = None
    cert: Optional[str] = None
    for tok in left_tokens:
        if kex is None and tok in _KEY_EXCHANGE_TOKENS:
            kex = tok
        elif cert is None and tok in _CERT_ALGO_TOKENS:
            cert = tok

    # Right: <ENC_PARTS>_<MAC>
    right_tokens = right.split("_")
    mac: Optional[str] = None
    enc_tokens_r: list[str] = list(right_tokens)
    for i in range(len(right_tokens) - 1, -1, -1):
        if right_tokens[i] in _MAC_TOKENS:
            mac = right_tokens[i]
            enc_tokens_r = right_tokens[:i]
            break

    enc_candidate = "_".join(enc_tokens_r)
    enc = enc_candidate if enc_candidate in _ENCRYPTION_TOKENS else enc_candidate or None

    return ParsedCipher(
        raw=name,
        key_exchange=kex,
        certificate_algorithm=cert,
        encryption_algorithm=enc or None,
        mac_algorithm=mac,
    )


def _parse_openssl(name: str) -> ParsedCipher:
    """
    OpenSSL dash-separated form: ECDHE-RSA-AES256-GCM-SHA384

    Strategy: scan left-to-right: kex -> cert -> enc bucket -> mac
    """
    tokens = name.upper().split("-")
    kex: Optional[str] = None
    cert: Optional[str] = None
    enc_parts: list[str] = []

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if kex is None and cert is None and tok in _KEY_EXCHANGE_TOKENS and tok not in _CERT_ALGO_TOKENS:
            kex = tok
        elif kex is not None and cert is None and tok in _CERT_ALGO_TOKENS:
            cert = tok
        else:
            enc_parts.append(tok)
        i += 1

    mac: Optional[str] = None
    if enc_parts and enc_parts[-1] in _MAC_TOKENS:
        mac = enc_parts.pop()

    # Normalise to underscores for consistency: AES256-GCM -> AES256_GCM
    enc_raw = "_".join(enc_parts) if enc_parts else None
    enc: Optional[str] = enc_raw if enc_raw else None

    return ParsedCipher(
        raw=name,
        key_exchange=kex,
        certificate_algorithm=cert,
        encryption_algorithm=enc,
        mac_algorithm=mac,
    )


def parse_cipher(cipher_name: Optional[str]) -> ParsedCipher:
    """
    Route a cipher suite name to the appropriate format parser.

    Returns a ParsedCipher with all components None for unknown/empty input.
    Never raises.
    """
    if not cipher_name:
        return ParsedCipher(raw="")

    name = cipher_name.strip()

    try:
        if _is_iana_tls13(name):
            result = _parse_iana_tls13(name)
        elif _is_iana_tls12(name):
            result = _parse_iana_tls12(name)
        elif _is_openssl(name):
            result = _parse_openssl(name)
        else:
            logger.debug("[cbom] Unrecognised cipher format: %r", name)
            return ParsedCipher(raw=name)

        logger.debug("[cbom] Parsed %r -> %r", name, result)
        return result

    except Exception as exc:  # noqa: BLE001
        logger.warning("[cbom] Cipher parse exception for %r: %s", name, exc)
        return ParsedCipher(raw=name)


# ═══════════════════════════════════════════════════════════════════════════ #
# Section 3 — TLSScanResult -> CBOMRecord transformer                         #
# ═══════════════════════════════════════════════════════════════════════════ #

def build_cbom_record(scan: TLSScanResult) -> CBOMRecord:
    """
    Pure function: transform one TLSScanResult into a CBOMRecord.
    No I/O, no side effects.
    """
    parsed = parse_cipher(scan.cipher)
    tls_version = normalize_tls_version(scan.tls_version)
    cert = scan.certificate

    return CBOMRecord(
        asset=scan.host,
        port=scan.port,
        tls_version=tls_version,
        cipher_suite=scan.cipher,
        key_exchange=parsed.key_exchange,
        encryption_algorithm=parsed.encryption_algorithm,
        mac_algorithm=parsed.mac_algorithm,
        certificate_algorithm=parsed.certificate_algorithm,
        certificate_signature_algorithm=(cert.signature_algorithm if cert else None),
        certificate_expiry=(cert.not_after if cert else None),
        certificate_subject=(cert.subject if cert else None),
        certificate_issuer=(cert.issuer if cert else None),
        certificate_verified=not bool(scan.certificate_error),
        certificate_error=scan.certificate_error,
    )


def generate_cbom(scan_results: list[TLSScanResult]) -> list[CBOMRecord]:
    """
    Convert a list of TLSScanResult objects into CBOMRecord objects.
    Deduplicates on (asset, port) — last result for each pair wins.
    """
    seen: dict[tuple[str, int], CBOMRecord] = {}

    for result in scan_results:
        try:
            record = build_cbom_record(result)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[cbom] Failed to build record for %s:%d — %s",
                result.host, result.port, exc,
            )
            continue

        # Ensure required deduplication fields are present
        if not record.asset or record.port is None:
            logger.warning(
                "[cbom] Skipping record with missing asset/port: asset=%r port=%r",
                record.asset, record.port,
            )
            continue

        key: tuple[str, int] = (record.asset, int(record.port))
        if key in seen:
            logger.debug("[cbom] Deduplicating %s:%d — keeping latest", *key)
        seen[key] = record

    records = list(seen.values())
    logger.info(
        "[cbom] Generated %d CBOM records from %d scan results",
        len(records), len(scan_results),
    )
    return records


# ═══════════════════════════════════════════════════════════════════════════ #
# Section 4 — MongoDB persistence                                              #
# ═══════════════════════════════════════════════════════════════════════════ #

def _record_to_document(record: CBOMRecord) -> dict:
    """
    Convert a CBOMRecord into a MongoDB document.

    scanned_at is set here (UTC now) so every upsert carries a fresh timestamp.
    MongoDB will assign _id automatically on insert.
    """
    return {
        "asset":                           record.asset,
        "port":                            record.port,
        "tls_version":                     record.tls_version,
        "cipher_suite":                    record.cipher_suite,
        "key_exchange":                    record.key_exchange,
        "encryption_algorithm":            record.encryption_algorithm,
        "mac_algorithm":                   record.mac_algorithm,
        "certificate_algorithm":           record.certificate_algorithm,
        "certificate_signature_algorithm": record.certificate_signature_algorithm,
        "certificate_expiry":              record.certificate_expiry,
        "certificate_subject":             record.certificate_subject,
        "certificate_issuer":              record.certificate_issuer,
        "certificate_verified":            record.certificate_verified,
        "certificate_error":               record.certificate_error,
        "scanned_at":                      datetime.now(tz=timezone.utc),
    }


def save_cbom_records(records: list[CBOMRecord]) -> list[CBOMRecord]:
    """
    Upsert CBOM records into MongoDB using bulk_write for efficiency.

    Uses ReplaceOne(upsert=True) per record:
      - New (asset, port) pairs are inserted.
      - Existing pairs are fully replaced with the latest scan data.
      - scanned_at is always refreshed.

    ordered=False lets MongoDB continue on individual write errors and
    batch-report failures at the end via BulkWriteError.

    Args:
        records: Deduplicated CBOMRecord list to persist.

    Returns:
        The same list (caller already has the Pydantic objects).

    Raises:
        RuntimeError: Wraps MongoDB errors with actionable context.
    """
    if not records:
        logger.info("[cbom] No records to save.")
        return []

    # If pymongo is not available, surface a clear error to the caller
    if ReplaceOne is None:
        raise RuntimeError(
            "pymongo is not installed in this environment — cannot persist CBOM records."
        )

    collection = get_cbom_collection()

    operations = [
        ReplaceOne(
            filter={"asset": r.asset, "port": r.port},
            replacement=_record_to_document(r),
            upsert=True,
        )
        for r in records
    ]

    try:
        result = collection.bulk_write(operations, ordered=False)
        logger.info(
            "[cbom] MongoDB upsert complete — inserted=%d, upserted=%d, modified=%d",
            getattr(result, "inserted_count", 0),
            getattr(result, "upserted_count", 0),
            getattr(result, "modified_count", 0),
        )
        return records

    except BulkWriteError as exc:
        write_errors = getattr(exc, "details", {}).get("writeErrors", [])
        logger.error(
            "[cbom] BulkWriteError — %d error(s). First: %s",
            len(write_errors),
            write_errors[0] if write_errors else "unknown",
        )
        raise RuntimeError(
            f"MongoDB bulk write partially failed: {len(write_errors)} error(s). "
            "Check server logs for details."
        ) from exc

    except PyMongoError as exc:
        logger.exception("[cbom] MongoDB error during save: %s", exc)
        raise RuntimeError(f"MongoDB error while saving CBOM records: {exc}") from exc

    except Exception as exc:  # noqa: BLE001
        logger.exception("[cbom] Unexpected error during save: %s", exc)
        raise RuntimeError(f"Unexpected error saving CBOM records: {exc}") from exc


# ═══════════════════════════════════════════════════════════════════════════ #
# Section 5 — Public pipeline entry point                                     #
# ═══════════════════════════════════════════════════════════════════════════ #

def process_and_store_cbom(scan_results: list[TLSScanResult]) -> list[CBOMRecord]:
    """
    Full CBOM pipeline: transform -> deduplicate -> persist -> return.

    This is the single function called by the API layer.

    Args:
        scan_results: Flat list of TLSScanResult from the TLS scanner.

    Returns:
        List of CBOMRecord — one per unique (asset, port) stored.
    """
    if not scan_results:
        logger.info("[cbom] No TLS scan results provided — nothing to do.")
        return []

    records = generate_cbom(scan_results)
    return save_cbom_records(records)