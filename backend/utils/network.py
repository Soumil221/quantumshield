# utils/network.py
#
# Low-level socket and TLS connection primitives for Quantum Shield.
#
# Two-pass probe strategy:
#   Pass 1 — strict:    ssl.create_default_context() with full CA verification
#                       and hostname checking. Represents real-world validity.
#   Pass 2 — fallback:  CERT_NONE context, only reached when Pass 1 raises
#                       SSLCertVerificationError (expired/self-signed/mismatch).
#                       Captures cipher + version + raw cert bytes so the scanner
#                       can still report *what* TLS is configured, even when the
#                       certificate itself is broken.
#
# All other exceptions (ConnectionRefused, Timeout, generic SSLError) are caught
# and returned as ConnectionFailure — never raised to callers.

import logging
import socket
import ssl
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ── Tuneable defaults ─────────────────────────────────────────────────────── #

CONNECT_TIMEOUT: float = 10.0

TLS_CANDIDATE_PORTS: frozenset[int] = frozenset(
    [443, 8443, 465, 587, 993, 995, 8444, 4443, 2083, 2087, 2096]
)


# ── Result types ──────────────────────────────────────────────────────────── #

@dataclass
class RawTLSData:
    """
    Everything extractable from a single TLS connection.

    .verified = True  → CA chain + hostname both checked and passed.
    .verified = False → fallback probe; cert may be expired/self-signed.
    """
    host: str
    port: int
    tls_version: Optional[str]
    cipher_name: Optional[str]
    cipher_bits: Optional[int]
    cert_der: Optional[bytes]
    cert_dict: Optional[dict]
    verified: bool = True
    cert_error: Optional[str] = None


@dataclass
class ConnectionFailure:
    """Returned when TCP connection or TLS handshake cannot be completed."""
    host: str
    port: int
    reason: str


# ── Internal helpers ──────────────────────────────────────────────────────── #

def is_tls_port(port: int) -> bool:
    """Return True if *port* is a recognised TLS candidate."""
    return port in TLS_CANDIDATE_PORTS


def _make_strict_context() -> ssl.SSLContext:
    """Full CA verification + hostname checking — the correct production default."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _make_fallback_context() -> ssl.SSLContext:
    """
    Verification-disabled context.

    ONLY used as a second-pass fallback after SSLCertVerificationError so we
    can still capture cipher suite and cert bytes for security reporting.
    Never used as a first-pass context.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _open_tls_socket(
    host: str,
    port: int,
    ctx: ssl.SSLContext,
    sni: str,
    timeout: float,
) -> ssl.SSLSocket:
    """
    Open a TCP connection and complete a TLS handshake.

    Returns the live SSLSocket on success; raises on any failure.
    The caller owns the socket and must close it.
    """
    raw_sock = socket.create_connection((host, port), timeout=timeout)
    raw_sock.settimeout(timeout)
    return ctx.wrap_socket(raw_sock, server_hostname=sni)


def _drain_socket(
    tls_sock: ssl.SSLSocket,
    host: str,
    port: int,
    *,
    verified: bool,
    cert_error: Optional[str] = None,
) -> RawTLSData:
    """Extract all useful fields from an open SSLSocket into a RawTLSData."""
    cipher_info = tls_sock.cipher()
    return RawTLSData(
        host=host,
        port=port,
        tls_version=tls_sock.version(),
        cipher_name=cipher_info[0] if cipher_info else None,
        cipher_bits=cipher_info[2] if cipher_info else None,
        cert_dict=tls_sock.getpeercert(),
        cert_der=tls_sock.getpeercert(binary_form=True),
        verified=verified,
        cert_error=cert_error,
    )


def _close(sock: Optional[ssl.SSLSocket]) -> None:
    """Silently close a socket, ignoring any errors."""
    if sock is not None:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass


# ── Public entry point ────────────────────────────────────────────────────── #

def probe_tls(
    host: str,
    port: int,
    *,
    timeout: float = CONNECT_TIMEOUT,
    server_name: Optional[str] = None,
) -> RawTLSData | ConnectionFailure:
    """
    Perform a TLS handshake against host:port and return structured results.

    Strategy
    --------
    Pass 1 — strict (ssl.create_default_context, CERT_REQUIRED, check_hostname=True)
        Attempt a fully-verified TLS connection.  This is what a real browser does.

    Pass 2 — fallback (CERT_NONE, check_hostname=False)
        Triggered ONLY when Pass 1 raises SSLCertVerificationError.
        Lets us still capture cipher suite + cert bytes for expired/self-signed
        certs, which is exactly what a security scanner needs to report on.

    Any other failure (connection refused, timeout, generic SSLError) returns
    a ConnectionFailure immediately — no fallback is attempted.
    """
    sni = server_name or host
    logger.debug("[tls-probe] %s:%d  sni=%s  timeout=%.1fs", host, port, sni, timeout)

    # ── Pass 1: strict, fully-verified ───────────────────────────────────── #
    tls_sock: Optional[ssl.SSLSocket] = None
    cert_error: Optional[str] = None

    try:
        tls_sock = _open_tls_socket(host, port, _make_strict_context(), sni, timeout)
        data = _drain_socket(tls_sock, host, port, verified=True)
        logger.debug(
            "[tls-probe] VERIFIED %s:%d  %s / %s (%s bits)",
            host, port, data.tls_version, data.cipher_name, data.cipher_bits,
        )
        return data

    except ssl.SSLCertVerificationError as exc:
        # Handshake worked but certificate failed validation.
        # Save the error and fall through to Pass 2.
        cert_error = str(exc)
        logger.warning(
            "[tls-probe] Cert verification failed %s:%d — %s — retrying unverified",
            host, port, cert_error,
        )

    except ssl.SSLError as exc:
        return ConnectionFailure(
            host=host, port=port, reason=f"SSL error: {exc.reason or str(exc)}"
        )

    except ConnectionRefusedError:
        logger.debug("[tls-probe] Connection refused %s:%d", host, port)
        return ConnectionFailure(host=host, port=port, reason="Connection refused")

    except (TimeoutError, socket.timeout):
        return ConnectionFailure(
            host=host, port=port, reason=f"Timed out after {timeout}s"
        )

    except OSError as exc:
        return ConnectionFailure(
            host=host, port=port, reason=f"OS error: {exc.strerror or str(exc)}"
        )

    except Exception as exc:  # noqa: BLE001
        logger.warning("[tls-probe] Unexpected error %s:%d — %s", host, port, exc)
        return ConnectionFailure(
            host=host, port=port, reason=f"{type(exc).__name__}: {exc}"
        )

    finally:
        _close(tls_sock)
        tls_sock = None

    # ── Pass 2: fallback — cert verification disabled ─────────────────────── #
    # Reached only after SSLCertVerificationError; cert_error is set.
    try:
        tls_sock = _open_tls_socket(host, port, _make_fallback_context(), sni, timeout)
        data = _drain_socket(tls_sock, host, port, verified=False, cert_error=cert_error)
        logger.info(
            "[tls-probe] FALLBACK %s:%d  %s / %s — cert error: %s",
            host, port, data.tls_version, data.cipher_name, cert_error,
        )
        return data

    except Exception as exc:  # noqa: BLE001
        logger.warning("[tls-probe] Fallback also failed %s:%d — %s", host, port, exc)
        return ConnectionFailure(
            host=host,
            port=port,
            reason=f"Cert invalid ({cert_error}); fallback failed: {type(exc).__name__}: {exc}",
        )

    finally:
        _close(tls_sock)