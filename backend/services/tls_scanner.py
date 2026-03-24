# services/tls_scanner.py
#
# TLS & Cryptography Scanner — Phase 3 of Quantum Shield.
#
# Pipeline (per asset):
#   1. Filter ports → keep only TLS candidates (443, 8443, …)
#   2. Probe each host:port → perform real TLS handshake via utils.network
#   3. Parse raw cert dict → extract subject, issuer, expiry, signature algo
#   4. Classify findings → flag weak ciphers, old TLS versions, near-expiry
#   5. Assemble TLSScanResult objects and return
#
# Concurrency:
#   TLS handshakes are I/O-bound and blocking (ssl.SSLSocket).  We run them
#   concurrently in a ThreadPoolExecutor.  For production workloads with
#   hundreds of assets, consider replacing with asyncio + ssl streams.

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional, cast

from models import (
    CertificateInfo,
    DiscoveredAsset,
    TLSScanResult,
    TLSScanFailure,
    TLSAssetResult,
)
from utils.network import (
    ConnectionFailure,
    RawTLSData,
    TLS_CANDIDATE_PORTS,
    is_tls_port,
    probe_tls,
)

logger = logging.getLogger(__name__)

# ── Security classification constants ────────────────────────────────────── #

# TLS versions considered insecure — flag them in results.
WEAK_TLS_VERSIONS: frozenset[str] = frozenset(["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"])

# Cipher substrings that indicate known-weak algorithms.
WEAK_CIPHER_PATTERNS: tuple[str, ...] = (
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON", "ADH", "AECDH",
)

# Certificate expiry warning thresholds.
EXPIRY_WARNING_DAYS: int = 30
EXPIRY_CRITICAL_DAYS: int = 7

# Worker counts — adjust based on your network conditions.
TLS_WORKERS: int = 20
CONNECT_TIMEOUT: float = 10.0    # seconds per handshake attempt


# ── Cryptography library availability check ───────────────────────────────── #
# We attempt to import once at module load and degrade gracefully if absent.

try:
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives.asymmetric import (
        rsa as _rsa,
        ec as _ec,
        dsa as _dsa,
        ed25519 as _ed25519,
        ed448 as _ed448,
    )
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover
    from typing import Any, cast

    _CRYPTOGRAPHY_AVAILABLE = False
    # Use Any-typed placeholders so static analyzers allow attribute access.
    _x509: Any = cast(Any, None)
    _rsa: Any = cast(Any, None)
    _ec: Any = cast(Any, None)
    _dsa: Any = cast(Any, None)
    _ed25519: Any = cast(Any, None)
    _ed448: Any = cast(Any, None)
    logger.warning(
        "[tls] 'cryptography' package not installed — "
        "certificate signature algorithms will be unavailable. "
        "Run: pip install cryptography"
    )


# ── Step 1 — Port filtering ───────────────────────────────────────────────── #

def filter_tls_ports(ports: list[int]) -> list[int]:
    """
    Return only the ports from *ports* that are TLS candidates.

    Skips plaintext ports (80, 22, 3306, …) to avoid wasting time on
    connections that will never speak TLS.
    """
    return [p for p in ports if is_tls_port(p)]


# ── Step 2 — Certificate parsing ─────────────────────────────────────────── #

def _parse_rdns(rdns: tuple) -> str:
    """
    Flatten Python's nested RDN tuple into a readable DN string.

    Python's ssl.getpeercert() returns the subject/issuer as a tuple of
    tuples, e.g.:
        ((('commonName', 'example.com'),), (('organizationName', 'ACME'),))

    This function produces: "commonName=example.com, organizationName=ACME"
    """
    if not rdns:
        return ""
    parts: list[str] = []
    for rdn in rdns:
        for attr_type, attr_value in rdn:
            parts.append(f"{attr_type}={attr_value}")
    return ", ".join(parts)


def _parse_expiry(not_after: Optional[str]) -> Optional[str]:
    """
    Normalise the notAfter string from ssl.getpeercert() into ISO-8601 UTC.

    Python returns: "May 15 12:00:00 2025 GMT"
    We return:      "2025-05-15T12:00:00+00:00"
    """
    if not not_after:
        return None
    try:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        # Return the raw string rather than None so the data isn't lost.
        return not_after


def _days_until_expiry(not_after: Optional[str]) -> Optional[int]:
    """Return number of days until cert expiry, or None if unparseable."""
    if not not_after:
        return None
    try:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        dt = dt.replace(tzinfo=timezone.utc)
        delta = dt - datetime.now(tz=timezone.utc)
        return delta.days
    except ValueError:
        return None


def _extract_san(cert_dict: dict) -> list[str]:
    """
    Extract Subject Alternative Names from the decoded cert dict.

    Returns a list of strings like ['DNS:example.com', 'DNS:www.example.com'].
    """
    san_list: list[str] = []
    for name_type, name_value in cert_dict.get("subjectAltName", []):
        san_list.append(f"{name_type}:{name_value}")
    return san_list


def _extract_signature_algorithm(cert_der: Optional[bytes]) -> str:
    """
    Extract the human-readable signature algorithm from raw DER cert bytes.

    Uses the 'cryptography' library when available to produce strings like:
        "sha256WithRSAEncryption"
        "ecdsa-with-SHA256"
        "ed25519"

    Falls back gracefully with a clear message if the library is absent or
    parsing fails.

    Args:
        cert_der: Raw DER-encoded certificate bytes from
                  ssl.SSLSocket.getpeercert(binary_form=True).

    Returns:
        A human-readable signature algorithm string, never None.
    """
    if not cert_der:
        return "unavailable (no DER bytes)"

    if not _CRYPTOGRAPHY_AVAILABLE:
        return "unavailable (install cryptography: pip install cryptography)"

    try:
        cert_obj = _x509.load_der_x509_certificate(cert_der)

        # Prefer the hash algorithm name combined with the key type —
        # this mirrors the OpenSSL-style naming convention.
        hash_algo = cert_obj.signature_hash_algorithm
        pub_key = cert_obj.public_key()

        if hash_algo is None:
            # Pure EdDSA algorithms (Ed25519, Ed448) have no separate hash.
            if isinstance(pub_key, _ed25519.Ed25519PublicKey):
                return "ed25519"
            if isinstance(pub_key, _ed448.Ed448PublicKey):
                return "ed448"
            # Unknown — fall back to OID dotted string.
            return cert_obj.signature_algorithm_oid.dotted_string

        hash_name = hash_algo.name.lower()   # e.g. "sha256"

        if isinstance(pub_key, _rsa.RSAPublicKey):
            return f"sha{hash_name.replace('sha', '')}WithRSAEncryption"
        if isinstance(pub_key, _ec.EllipticCurvePublicKey):
            return f"ecdsa-with-{hash_name.upper().replace('SHA', 'SHA')}"
        if isinstance(pub_key, _dsa.DSAPublicKey):
            return f"dsa-with-{hash_name.upper()}"

        # Fallback for any other key type — still better than "unavailable".
        return f"{hash_name}WithUnknownKey"

    except Exception as exc:  # noqa: BLE001
        logger.debug("[tls] Could not extract signature algorithm from DER: %s", exc)
        return f"unavailable (parse error: {type(exc).__name__})"


def parse_certificate(
    cert_dict: Optional[dict],
    cert_der: Optional[bytes] = None,
) -> Optional[CertificateInfo]:
    """
    Convert Python's raw cert dict into a structured CertificateInfo object.

    Python's ssl.getpeercert() returns a dict with keys like:
        subject, issuer, notBefore, notAfter, serialNumber, version,
        subjectAltName, OCSP, caIssuers, crlDistributionPoints

    signature_algorithm is extracted from the DER bytes via the 'cryptography'
    library (e.g. "sha256WithRSAEncryption").  Falls back gracefully if the
    library is unavailable or cert_der is not provided.

    Args:
        cert_dict: Decoded certificate dict from ssl.SSLSocket.getpeercert().
        cert_der:  Raw DER bytes from ssl.SSLSocket.getpeercert(binary_form=True).
                   Optional but required for signature algorithm extraction.
    """
    if not cert_dict:
        return None

    not_after_raw: Optional[str] = cert_dict.get("notAfter")
    days_left = _days_until_expiry(not_after_raw)

    # Determine expiry status for quick triage
    if days_left is None:
        expiry_status = "unknown"
    elif days_left < 0:
        expiry_status = "expired"
    elif days_left <= EXPIRY_CRITICAL_DAYS:
        expiry_status = "critical"
    elif days_left <= EXPIRY_WARNING_DAYS:
        expiry_status = "warning"
    else:
        expiry_status = "valid"

    return CertificateInfo(
        subject=_parse_rdns(cert_dict.get("subject", ())),
        issuer=_parse_rdns(cert_dict.get("issuer", ())),
        serial_number=cert_dict.get("serialNumber"),
        not_before=cert_dict.get("notBefore"),
        not_after=_parse_expiry(not_after_raw),
        days_until_expiry=days_left,
        expiry_status=expiry_status,
        signature_algorithm=_extract_signature_algorithm(cert_der),
        subject_alt_names=_extract_san(cert_dict),
        version=cert_dict.get("version"),
        ocsp=list(cert_dict.get("OCSP", [])),
        ca_issuers=list(cert_dict.get("caIssuers", [])),
    )


# ── Step 3 — Security classification ─────────────────────────────────────── #

def classify_tls_version(version: Optional[str]) -> str:
    """Return 'weak', 'acceptable', or 'strong' for a TLS version string."""
    if version is None:
        return "unknown"
    if version in WEAK_TLS_VERSIONS:
        return "weak"
    if version == "TLSv1.2":
        return "acceptable"
    return "strong"   # TLSv1.3


def classify_cipher(cipher: Optional[str]) -> str:
    """Return 'weak' if the cipher name contains any known-weak pattern."""
    if cipher is None:
        return "unknown"
    upper = cipher.upper()
    for pattern in WEAK_CIPHER_PATTERNS:
        if pattern in upper:
            return "weak"
    return "strong"


def _build_warnings(
    tls_version: Optional[str],
    cipher_name: Optional[str],
    cert: Optional[CertificateInfo],
    cert_error: Optional[str],
) -> list[str]:
    """
    Produce a human-readable list of security warnings for a single result.

    Returns an empty list if no issues are found — a clean result.
    """
    warnings: list[str] = []

    if classify_tls_version(tls_version) == "weak":
        warnings.append(f"Weak TLS version in use: {tls_version}")

    if classify_cipher(cipher_name) == "weak":
        warnings.append(f"Weak cipher suite in use: {cipher_name}")

    if cert_error:
        warnings.append(f"Certificate error: {cert_error}")

    if cert:
        if cert.expiry_status == "expired":
            warnings.append(f"Certificate is EXPIRED (expired {abs(cert.days_until_expiry or 0)} days ago)")
        elif cert.expiry_status == "critical":
            warnings.append(f"Certificate expires in {cert.days_until_expiry} days (CRITICAL)")
        elif cert.expiry_status == "warning":
            warnings.append(f"Certificate expires in {cert.days_until_expiry} days (WARNING)")

    return warnings


# ── Step 4 — Per host:port scanner ───────────────────────────────────────── #

def scan_single(host: str, port: int) -> TLSScanResult | TLSScanFailure:
    """
    Perform a full TLS scan of a single host:port.

    Returns:
        TLSScanResult — on successful handshake (cert may still have errors).
        TLSScanFailure — when the TCP/TLS connection itself cannot be made.
    """
    logger.info("[tls] Scanning %s:%d", host, port)

    outcome: RawTLSData | ConnectionFailure = probe_tls(
        host,
        port,
        timeout=CONNECT_TIMEOUT,
        server_name=host,    # always use the hostname for SNI
    )

    if isinstance(outcome, ConnectionFailure):
        logger.debug("[tls] %s:%d — failure: %s", host, port, outcome.reason)
        return TLSScanFailure(host=host, port=port, reason=outcome.reason)

    # outcome is RawTLSData from here — help static type-checkers with a cast
    outcome = cast(RawTLSData, outcome)

    # Pass both cert_dict AND cert_der so signature_algorithm can be extracted
    cert_info = parse_certificate(outcome.cert_dict, outcome.cert_der)
    warnings = _build_warnings(
        outcome.tls_version,
        outcome.cipher_name,
        cert_info,
        outcome.cert_error,
    )

    result = TLSScanResult(
        host=host,
        port=port,
        tls_version=outcome.tls_version,
        cipher=outcome.cipher_name,
        cipher_bits=outcome.cipher_bits,
        tls_version_grade=classify_tls_version(outcome.tls_version),
        cipher_grade=classify_cipher(outcome.cipher_name),
        certificate=cert_info,
        certificate_error=outcome.cert_error,
        warnings=warnings,
    )

    logger.info(
        "[tls] %s:%d — %s / %s | cert_expiry=%s | warnings=%d",
        host, port,
        result.tls_version, result.cipher,
        cert_info.expiry_status if cert_info else "no-cert",
        len(warnings),
    )
    return result


# ── Step 5 — Public entry point ───────────────────────────────────────────── #

def scan_tls_assets(assets: list[DiscoveredAsset]) -> list[TLSAssetResult]:
    """
    Run TLS scans across all TLS-capable ports on every asset.

    Algorithm:
        1. Expand assets → (host, port) pairs, filtering non-TLS ports.
        2. Deduplicate pairs (same host:port from multiple assets is scanned once).
        3. Run scan_single() concurrently across all pairs.
        4. Group results by host and return TLSAssetResult list.

    Args:
        assets: Output from the asset discovery module.

    Returns:
        One TLSAssetResult per host that had at least one TLS-candidate port.
        Hosts with no TLS ports are omitted entirely.
    """
    # ── Build deduplicated work list ─────────────────────────────────────── #
    seen: set[tuple[str, int]] = set()
    pairs: list[tuple[str, int]] = []

    for asset in assets:
        tls_ports = filter_tls_ports(asset.ports)
        if not tls_ports:
            logger.debug("[tls] %s — no TLS ports in %s, skipping", asset.host, asset.ports)
            continue
        for port in tls_ports:
            key = (asset.host, port)
            if key not in seen:
                seen.add(key)
                pairs.append(key)

    if not pairs:
        logger.warning("[tls] No TLS-capable ports found across %d assets.", len(assets))
        return []

    logger.info("[tls] Scanning %d host:port pairs (workers=%d) …", len(pairs), TLS_WORKERS)

    # ── Concurrent scanning ──────────────────────────────────────────────── #
    # Collect raw results keyed by host
    host_results: dict[str, list[TLSScanResult | TLSScanFailure]] = {}

    with ThreadPoolExecutor(max_workers=TLS_WORKERS) as pool:
        future_to_pair = {
            pool.submit(scan_single, host, port): (host, port)
            for host, port in pairs
        }
        for future in as_completed(future_to_pair):
            host, port = future_to_pair[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                logger.exception("[tls] Worker crashed for %s:%d — %s", host, port, exc)
                result = TLSScanFailure(
                    host=host,
                    port=port,
                    reason=f"Worker exception: {type(exc).__name__}: {exc}",
                )
            host_results.setdefault(host, []).append(result)

    # ── Group into TLSAssetResult ────────────────────────────────────────── #
    asset_results: list[TLSAssetResult] = []
    for host, results in sorted(host_results.items()):
        successes = [r for r in results if isinstance(r, TLSScanResult)]
        failures  = [r for r in results if isinstance(r, TLSScanFailure)]

        # Overall host grade: worst grade across all scanned ports
        grades = [r.tls_version_grade for r in successes]
        if not grades:
            overall_grade = "no_tls"
        elif "weak" in grades:
            overall_grade = "weak"
        elif "acceptable" in grades:
            overall_grade = "acceptable"
        else:
            overall_grade = "strong"

        asset_results.append(
            TLSAssetResult(
                host=host,
                overall_grade=overall_grade,
                scanned_ports=[r.port for r in results],
                results=successes,
                failures=failures,
            )
        )

    logger.info(
        "[tls] Completed. %d hosts scanned, %d successful port results, %d failures.",
        len(asset_results),
        sum(len(a.results) for a in asset_results),
        sum(len(a.failures) for a in asset_results),
    )
    return asset_results