"""
Quantum Risk Analyzer — evaluates cryptographic risk of TLS assets.

Scoring model (0–10, higher = more dangerous):
  - TLS version risk     : 0–4 points
  - Key exchange risk    : 0–3 points
  - Cipher/enc algorithm : 0–2 points
  - Certificate alg risk : 0–1 point

Risk levels:
  CRITICAL  : 8–10
  HIGH      : 6–7
  MEDIUM    : 4–5
  LOW       : 2–3
  SAFE      : 0–1
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Risk scoring tables
# ---------------------------------------------------------------------------

# TLS version → (score, reason)
_TLS_VERSION_RISK: dict[str, tuple[int, str]] = {
    "SSLv2":   (4, "SSLv2 is completely broken and deprecated"),
    "SSLv3":   (4, "SSLv3 is vulnerable to POODLE and deprecated"),
    "TLSv1":   (3, "TLS 1.0 is deprecated (RFC 8996), vulnerable to BEAST/POODLE"),
    "TLSv1.0": (3, "TLS 1.0 is deprecated (RFC 8996), vulnerable to BEAST/POODLE"),
    "TLSv1.1": (2, "TLS 1.1 is deprecated (RFC 8996)"),
    "TLSv1.2": (1, "TLS 1.2 is acceptable but not quantum-safe"),
    "TLSv1.3": (0, "TLS 1.3 is the current recommended standard"),
}

# Key exchange algorithm → (score, reason)
# Matches substrings — checked in order, first match wins.
_KEY_EXCHANGE_RISK: list[tuple[str, int, str]] = [
    # Post-quantum / safe
    ("KYBER",       0, "KYBER is a NIST-approved post-quantum algorithm"),
    ("NTRU",        0, "NTRU is a post-quantum algorithm"),
    ("FRODO",       0, "FrodoKEM is a post-quantum algorithm"),
    ("X25519MLKEM", 0, "X25519MLKEM is a hybrid post-quantum key exchange"),
    ("MLKEM",       0, "ML-KEM (Kyber) is a NIST PQC standard"),
    # Hybrid PQ
    ("X25519",      0, "X25519 provides strong forward secrecy"),
    ("X448",        0, "X448 provides strong forward secrecy"),
    # ECDHE variants
    ("ECDHE",       1, "ECDHE provides forward secrecy but is not quantum-safe"),
    ("ECDH",        1, "ECDH provides forward secrecy but is not quantum-safe"),
    # DHE / DH
    ("DHE",         2, "DHE is not quantum-safe"),
    ("DH",          2, "DH is not quantum-safe"),
    # RSA key exchange (no forward secrecy + quantum-vulnerable)
    ("RSA",         3, "RSA key exchange has no forward secrecy and is quantum-vulnerable"),
    # Export / NULL
    ("EXPORT",      3, "EXPORT ciphers are intentionally weakened"),
    ("NULL",        3, "NULL key exchange provides no confidentiality"),
    ("ANON",        3, "Anonymous key exchange provides no authentication"),
]

# Encryption algorithm → (score, reason)
_ENCRYPTION_RISK: list[tuple[str, int, str]] = [
    # ChaCha20 / AES-GCM — strong
    ("CHACHA20",    0, "ChaCha20-Poly1305 is a modern AEAD cipher"),
    ("AES_256_GCM", 0, "AES-256-GCM is a strong AEAD cipher"),
    ("AES_128_GCM", 0, "AES-128-GCM is a strong AEAD cipher"),
    ("AES_256_CCM", 0, "AES-256-CCM is a strong AEAD cipher"),
    ("AES_128_CCM", 0, "AES-128-CCM is a strong AEAD cipher"),
    # AES-CBC — acceptable but not AEAD
    ("AES_256",     1, "AES-256-CBC is acceptable but not an AEAD mode"),
    ("AES_128",     1, "AES-128-CBC is acceptable but not an AEAD mode"),
    ("AES",         1, "AES-CBC mode is acceptable but not an AEAD mode"),
    # 3DES
    ("3DES",        2, "3DES is deprecated; vulnerable to SWEET32"),
    ("DES",         2, "DES is completely broken"),
    # RC4 / NULL / EXPORT
    ("RC4",         2, "RC4 is broken and must not be used"),
    ("EXPORT",      2, "EXPORT ciphers use deliberately weak encryption"),
    ("NULL",        2, "NULL encryption provides no confidentiality"),
]

# Certificate / signature algorithm → (score, reason)
_CERT_ALG_RISK: list[tuple[str, int, str]] = [
    # Dilithium / Falcon — PQC
    ("DILITHIUM",   0, "Dilithium is a NIST-approved post-quantum signature scheme"),
    ("FALCON",      0, "Falcon is a NIST-approved post-quantum signature scheme"),
    ("SPHINCS",     0, "SPHINCS+ is a NIST-approved post-quantum signature scheme"),
    # ECDSA / Ed25519 — good
    ("ECDSA",       0, "ECDSA is a modern signature algorithm"),
    ("ED25519",     0, "Ed25519 is a modern signature algorithm"),
    ("ED448",       0, "Ed448 is a modern signature algorithm"),
    # RSA — quantum-vulnerable
    ("RSA",         1, "RSA signatures are quantum-vulnerable (Shor's algorithm)"),
    # MD5 / SHA1 — broken hash
    ("MD5",         1, "MD5-based signatures are cryptographically broken"),
    ("SHA1",        1, "SHA-1-based signatures are deprecated"),
]


# ---------------------------------------------------------------------------
# Public data classes
# ---------------------------------------------------------------------------

@dataclass
class RiskFinding:
    category: str          # "tls_version" | "key_exchange" | "encryption" | "certificate"
    detail: str            # human-readable context
    score_contribution: int
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | SAFE


@dataclass
class RiskAnalysisResult:
    asset: str
    port: int
    risk_score: int                        # 0–10
    risk_level: str                        # SAFE | LOW | MEDIUM | HIGH | CRITICAL
    risk_score_display: str                # e.g. "8/10"
    findings: list[RiskFinding] = field(default_factory=list)
    is_quantum_safe: bool = False
    quantum_safe_reason: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalize(value: Optional[str]) -> str:
    """Upper-case and replace hyphens/spaces with underscores for matching.

    Treat None or empty strings as the empty normalized form so callers
    don't need to guard against missing DB fields.
    """
    if not value:
        return ""
    return re.sub(r"[-\s]+", "_", value.upper())


def _score_to_level(score: int) -> str:
    if score >= 8:
        return "CRITICAL"
    if score >= 6:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score >= 2:
        return "LOW"
    return "SAFE"


def _match_list(
    value: Optional[str],
    table: list[tuple[str, int, str]],
) -> tuple[int, str]:
    """Return (score, reason) for the first matching entry in *table*."""
    norm = _normalize(value)
    for keyword, score, reason in table:
        if _normalize(keyword) in norm:
            return score, reason
    # Unknown — treat as neutral
    return 0, f"Unknown value '{value}' — treated as neutral"


def _is_pqc(key_exchange: Optional[str], cert_alg: Optional[str]) -> tuple[bool, str]:
    """Return (is_pqc, reason) based on key_exchange and cert algorithm."""
    pqc_ke = {"KYBER", "NTRU", "FRODO", "MLKEM", "X25519MLKEM"}
    pqc_sig = {"DILITHIUM", "FALCON", "SPHINCS"}

    norm_ke = _normalize(key_exchange)
    norm_sig = _normalize(cert_alg)

    ke_safe = any(_normalize(p) in norm_ke for p in pqc_ke)
    sig_safe = any(_normalize(p) in norm_sig for p in pqc_sig)

    if ke_safe and sig_safe:
        return True, "Both key exchange and certificate use post-quantum algorithms"
    if ke_safe:
        return False, "Key exchange is PQC but certificate signature is still classical"
    if sig_safe:
        return False, "Certificate uses PQC signature but key exchange is still classical"
    return False, "No post-quantum algorithms detected"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_risk(
    asset: str,
    port: int,
    tls_version: str,
    key_exchange: str,
    encryption_algorithm: str,
    certificate_algorithm: str,
    cipher_suite: str = "",
    mac_algorithm: str = "",
) -> RiskAnalysisResult:
    """
    Compute a risk score (0–10) and level for a single TLS endpoint.

    Parameters
    ----------
    asset                  : hostname or IP
    port                   : TCP port
    tls_version            : e.g. "TLSv1.2", "TLSv1.3"
    key_exchange           : e.g. "RSA", "ECDHE", "X25519"
    encryption_algorithm   : e.g. "AES_128_GCM", "RC4"
    certificate_algorithm  : e.g. "RSA", "ECDSA", "Dilithium3"
    cipher_suite           : full cipher string (optional, for display)
    mac_algorithm          : e.g. "SHA256" (optional, informational)
    """
    findings: list[RiskFinding] = []
    total_score = 0

    # --- TLS version (0–4) ---
    tls_score, tls_reason = _TLS_VERSION_RISK.get(
        tls_version, (1, f"Unrecognised TLS version '{tls_version}'")
    )
    total_score += tls_score
    findings.append(RiskFinding(
        category="tls_version",
        detail=f"{tls_version}: {tls_reason}",
        score_contribution=tls_score,
        severity=_score_to_level(tls_score * 2),  # scale for display
    ))

    # --- Key exchange (0–3) ---
    ke_score, ke_reason = _match_list(key_exchange, _KEY_EXCHANGE_RISK)
    total_score += ke_score
    findings.append(RiskFinding(
        category="key_exchange",
        detail=f"{key_exchange}: {ke_reason}",
        score_contribution=ke_score,
        severity=_score_to_level(ke_score * 2),
    ))

    # --- Encryption algorithm (0–2) ---
    enc_score, enc_reason = _match_list(encryption_algorithm, _ENCRYPTION_RISK)
    total_score += enc_score
    findings.append(RiskFinding(
        category="encryption",
        detail=f"{encryption_algorithm}: {enc_reason}",
        score_contribution=enc_score,
        severity=_score_to_level(enc_score * 3),
    ))

    # --- Certificate algorithm (0–1) ---
    cert_score, cert_reason = _match_list(certificate_algorithm, _CERT_ALG_RISK)
    total_score += cert_score
    findings.append(RiskFinding(
        category="certificate",
        detail=f"{certificate_algorithm}: {cert_reason}",
        score_contribution=cert_score,
        severity=_score_to_level(cert_score * 5),
    ))

    # Clamp to 0–10
    risk_score = max(0, min(10, total_score))
    risk_level = _score_to_level(risk_score)

    is_pqc, pqc_reason = _is_pqc(key_exchange, certificate_algorithm)

    return RiskAnalysisResult(
        asset=asset,
        port=port,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_score_display=f"{risk_score}/10",
        findings=findings,
        is_quantum_safe=is_pqc,
        quantum_safe_reason=pqc_reason,
    )


def analyze_risk_batch(
    records: list[dict],
) -> list[RiskAnalysisResult]:
    """
    Analyse a list of CBOM-style record dicts (as stored in MongoDB).
    Each dict must have the keys used by CBOMRecord.
    """
    results: list[RiskAnalysisResult] = []
    for rec in records:
        result = analyze_risk(
            asset=rec.get("asset", ""),
            port=int(rec.get("port", 0)),
            tls_version=rec.get("tls_version", ""),
            key_exchange=rec.get("key_exchange", ""),
            encryption_algorithm=rec.get("encryption_algorithm", ""),
            certificate_algorithm=rec.get("certificate_algorithm", ""),
            cipher_suite=rec.get("cipher_suite", ""),
            mac_algorithm=rec.get("mac_algorithm", ""),
        )
        results.append(result)
    return results