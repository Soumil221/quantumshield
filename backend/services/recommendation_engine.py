"""
Recommendation Engine — generates actionable remediation advice based on
risk findings produced by the Quantum Risk Analyzer.

Design:
- Rule-based: each Rule defines a condition (callable) and produces a
  Recommendation when triggered.
- Rules are evaluated against a RiskAnalysisResult, but also accept the
  raw field values for fine-grained matching.
- Output is a deduplicated, priority-sorted list of Recommendation objects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from services.risk_analyzer import RiskAnalysisResult, RiskFinding, _normalize


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Recommendation:
    priority: int          # 1 = most urgent
    category: str          # "tls_version" | "key_exchange" | "encryption" | "certificate" | "general"
    title: str             # short one-liner
    detail: str            # full explanation
    action: str            # concrete step to take
    reference: str = ""    # link or RFC


@dataclass
class RecommendationReport:
    asset: str
    port: int
    risk_score: int
    risk_level: str
    is_quantum_safe: bool
    recommendations: list[Recommendation] = field(default_factory=list)
    summary: str = ""


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

@dataclass
class _Rule:
    """A single recommendation rule."""
    id: str
    condition: Callable[[RiskAnalysisResult, dict], bool]
    recommendation: Recommendation


# Helper — check if a finding category has a score contribution >= threshold
def _finding_score(result: RiskAnalysisResult, category: str) -> int:
    for f in result.findings:
        if f.category == category:
            return f.score_contribution
    return 0


def _has_keyword(value: str, *keywords: str) -> bool:
    norm = _normalize(value)
    return any(_normalize(k) in norm for k in keywords)


_RULES: list[_Rule] = [

    # ── TLS Version ──────────────────────────────────────────────────────────

    _Rule(
        id="tls_ssl2",
        condition=lambda r, ctx: _has_keyword(ctx.get("tls_version", ""), "SSLv2"),
        recommendation=Recommendation(
            priority=1,
            category="tls_version",
            title="Immediately disable SSLv2",
            detail=(
                "SSLv2 is completely broken and has been deprecated since 1996. "
                "It is vulnerable to DROWN and multiple other attacks. "
                "Any server still offering SSLv2 is critically exposed."
            ),
            action=(
                "Disable SSLv2 in your server configuration immediately. "
                "For Nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                "For Apache: SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1"
            ),
            reference="https://datatracker.ietf.org/doc/html/rfc6176",
        ),
    ),

    _Rule(
        id="tls_ssl3",
        condition=lambda r, ctx: _has_keyword(ctx.get("tls_version", ""), "SSLv3"),
        recommendation=Recommendation(
            priority=1,
            category="tls_version",
            title="Immediately disable SSLv3",
            detail=(
                "SSLv3 is vulnerable to the POODLE attack and has been deprecated "
                "since RFC 7568 (2015). It must not be used in any production system."
            ),
            action=(
                "Disable SSLv3 in your server configuration. "
                "For Nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                "For Apache: SSLProtocol all -SSLv2 -SSLv3"
            ),
            reference="https://datatracker.ietf.org/doc/html/rfc7568",
        ),
    ),

    _Rule(
        id="tls_v1_deprecated",
        condition=lambda r, ctx: _has_keyword(ctx.get("tls_version", ""), "TLSv1.0", "TLSv1.1"),
        recommendation=Recommendation(
            priority=2,
            category="tls_version",
            title="Upgrade from TLS 1.0/1.1 to TLS 1.3",
            detail=(
                "TLS 1.0 and 1.1 were deprecated by RFC 8996 in March 2021. "
                "Both are vulnerable to BEAST, POODLE (TLS variant), and other attacks. "
                "PCI-DSS, HIPAA, and NIST SP 800-52r2 all require TLS 1.2+ at minimum."
            ),
            action=(
                "Upgrade your TLS configuration to require TLS 1.2 minimum, "
                "preferably TLS 1.3 only. "
                "For Nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                "For Apache: SSLProtocol TLSv1.2 TLSv1.3"
            ),
            reference="https://datatracker.ietf.org/doc/html/rfc8996",
        ),
    ),

    _Rule(
        id="tls_v12_not_v13",
        condition=lambda r, ctx: _has_keyword(ctx.get("tls_version", ""), "TLSv1.2"),
        recommendation=Recommendation(
            priority=3,
            category="tls_version",
            title="Upgrade to TLS 1.3",
            detail=(
                "TLS 1.2 is still acceptable but TLS 1.3 offers significant improvements: "
                "faster handshakes (1-RTT / 0-RTT), removal of legacy cipher suites, "
                "forward secrecy mandatory, and resistance to downgrade attacks."
            ),
            action=(
                "Enable TLS 1.3 on your server. Most modern stacks support it. "
                "For Nginx (≥1.13.0): ssl_protocols TLSv1.2 TLSv1.3; "
                "For Java: -Djdk.tls.client.protocols=TLSv1.3"
            ),
            reference="https://datatracker.ietf.org/doc/html/rfc8446",
        ),
    ),

    # ── Key Exchange ─────────────────────────────────────────────────────────

    _Rule(
        id="ke_rsa",
        condition=lambda r, ctx: (
            _finding_score(r, "key_exchange") >= 3 and
            _has_keyword(ctx.get("key_exchange", ""), "RSA")
        ),
        recommendation=Recommendation(
            priority=1,
            category="key_exchange",
            title="Replace RSA key exchange with ECDHE or PQC",
            detail=(
                "RSA key exchange (TLS_RSA_*) has no forward secrecy: compromise of "
                "the private key decrypts all past sessions. It is also quantum-vulnerable "
                "— Shor's algorithm can break RSA on a sufficiently large quantum computer. "
                "'Harvest now, decrypt later' attacks are already a documented threat."
            ),
            action=(
                "Disable all TLS_RSA_* cipher suites. "
                "Use ECDHE or, for quantum safety, ML-KEM / X25519MLKEM hybrid ciphers. "
                "For OpenSSL: set ECDHE ciphers, e.g. TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES256-GCM-SHA384"
            ),
            reference="https://csrc.nist.gov/projects/post-quantum-cryptography",
        ),
    ),

    _Rule(
        id="ke_not_pqc",
        condition=lambda r, ctx: not r.is_quantum_safe,
        recommendation=Recommendation(
            priority=2,
            category="key_exchange",
            title="Adopt post-quantum key exchange (ML-KEM / Kyber)",
            detail=(
                "Current ECDHE and DHE key exchange algorithms are vulnerable to "
                "Shor's algorithm on quantum computers. NIST finalized ML-KEM (Kyber-1024) "
                "as FIPS 203 in August 2024. Hybrid schemes (X25519MLKEM768) are already "
                "supported in BoringSSL, OpenSSL 3.x, and major cloud providers."
            ),
            action=(
                "Enable a hybrid post-quantum key exchange group: "
                "OpenSSL 3.x: set ssl_ecdh_curve X25519MLKEM768:X25519; "
                "nginx-quic with liboqs: ssl_ecdh_curve X25519MLKEM768; "
                "Review NIST FIPS 203 (ML-KEM) for implementation guidance."
            ),
            reference="https://doi.org/10.6028/NIST.FIPS.203",
        ),
    ),

    _Rule(
        id="ke_dh_no_fs",
        condition=lambda r, ctx: (
            _has_keyword(ctx.get("key_exchange", ""), "DH") and
            not _has_keyword(ctx.get("key_exchange", ""), "ECDHE", "DHE", "X25519", "X448")
        ),
        recommendation=Recommendation(
            priority=2,
            category="key_exchange",
            title="Enable forward secrecy with DHE or ECDHE",
            detail=(
                "Static DH key exchange does not provide forward secrecy. "
                "An attacker who obtains the server's private key can decrypt "
                "all previously recorded sessions."
            ),
            action=(
                "Replace static DH cipher suites with DHE or ECDHE variants. "
                "For DHE: ensure DH parameters are at least 2048-bit (prefer 4096-bit). "
                "For ECDHE: prefer P-256 or X25519."
            ),
            reference="https://www.rfc-editor.org/rfc/rfc7919",
        ),
    ),

    _Rule(
        id="ke_export_null_anon",
        condition=lambda r, ctx: _has_keyword(
            ctx.get("key_exchange", ""), "EXPORT", "NULL", "ANON"
        ),
        recommendation=Recommendation(
            priority=1,
            category="key_exchange",
            title="Disable EXPORT, NULL, and anonymous cipher suites immediately",
            detail=(
                "EXPORT ciphers use intentionally weakened key material (40-56 bit). "
                "NULL and anonymous cipher suites provide no authentication or no "
                "encryption, respectively. These are exploited by FREAK and LOGJAM attacks."
            ),
            action=(
                "Explicitly exclude these suites from your cipher list. "
                "OpenSSL string: !EXP:!NULL:!aNULL:!eNULL "
                "For Nginx: ssl_ciphers 'HIGH:!aNULL:!eNULL:!EXPORT:!NULL';"
            ),
            reference="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0204",
        ),
    ),

    # ── Encryption Algorithm ─────────────────────────────────────────────────

    _Rule(
        id="enc_rc4",
        condition=lambda r, ctx: _has_keyword(ctx.get("encryption_algorithm", ""), "RC4"),
        recommendation=Recommendation(
            priority=1,
            category="encryption",
            title="Disable RC4 immediately",
            detail=(
                "RC4 is a broken stream cipher with multiple known biases. "
                "It is prohibited by RFC 7465 in TLS contexts and is vulnerable to "
                "NOMORE, RC4NOMORE, and related attacks."
            ),
            action=(
                "Remove all RC4 cipher suites from your configuration. "
                "OpenSSL: !RC4 in your cipher string. "
                "IIS: disable RC4 in the Schannel registry."
            ),
            reference="https://datatracker.ietf.org/doc/html/rfc7465",
        ),
    ),

    _Rule(
        id="enc_3des",
        condition=lambda r, ctx: _has_keyword(ctx.get("encryption_algorithm", ""), "3DES", "DES"),
        recommendation=Recommendation(
            priority=1,
            category="encryption",
            title="Disable 3DES/DES — vulnerable to SWEET32",
            detail=(
                "3DES is vulnerable to the SWEET32 birthday attack (CVE-2016-2183) "
                "due to its 64-bit block size. It is deprecated in TLS (RFC 8996) "
                "and provides at most ~112 bits of security."
            ),
            action=(
                "Remove 3DES (DES-CBC3-SHA) from your cipher configuration. "
                "Prefer AES-128-GCM or AES-256-GCM AEAD ciphers. "
                "OpenSSL: !3DES:!DES in your cipher string."
            ),
            reference="https://sweet32.info/",
        ),
    ),

    _Rule(
        id="enc_aead_missing",
        condition=lambda r, ctx: (
            _finding_score(r, "encryption") >= 1 and
            not _has_keyword(ctx.get("encryption_algorithm", ""), "GCM", "CCM", "CHACHA20")
        ),
        recommendation=Recommendation(
            priority=2,
            category="encryption",
            title="Migrate to AEAD cipher modes (AES-GCM or ChaCha20-Poly1305)",
            detail=(
                "CBC-mode ciphers (even AES-CBC) are susceptible to padding-oracle attacks "
                "(POODLE, Lucky13, BEAST) and do not provide authenticated encryption. "
                "AEAD modes (GCM, CCM, ChaCha20-Poly1305) provide both confidentiality "
                "and integrity in a single primitive."
            ),
            action=(
                "Prioritise AEAD suites in your cipher order: "
                "TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, "
                "TLS_AES_128_GCM_SHA256 (TLS 1.3 only). "
                "For TLS 1.2: ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305"
            ),
            reference="https://datatracker.ietf.org/doc/html/rfc5116",
        ),
    ),

    # ── Certificate ───────────────────────────────────────────────────────────

    _Rule(
        id="cert_sha1_md5",
        condition=lambda r, ctx: _has_keyword(
            ctx.get("certificate_algorithm", ""), "SHA1", "MD5"
        ),
        recommendation=Recommendation(
            priority=2,
            category="certificate",
            title="Replace SHA-1/MD5 certificate with SHA-256 or stronger",
            detail=(
                "SHA-1 is collision-broken (SHAttered attack, 2017). MD5 was broken in 2004. "
                "All major browsers and CAs have deprecated SHA-1 certificates. "
                "Most CA/Browser Forum Baseline Requirements prohibit issuing SHA-1 certs."
            ),
            action=(
                "Request a new certificate using SHA-256 or SHA-384 signature algorithm. "
                "Most modern CAs default to SHA-256. "
                "OpenSSL: openssl req -new -sha256 -key server.key -out server.csr"
            ),
            reference="https://shattered.io/",
        ),
    ),

    _Rule(
        id="cert_rsa_sig",
        condition=lambda r, ctx: (
            _has_keyword(ctx.get("certificate_algorithm", ""), "RSA") and
            not _has_keyword(ctx.get("certificate_algorithm", ""), "ECDSA", "ED25519")
        ),
        recommendation=Recommendation(
            priority=3,
            category="certificate",
            title="Migrate RSA certificate to ECDSA or post-quantum signature",
            detail=(
                "RSA certificate signatures are quantum-vulnerable. Shor's algorithm "
                "can factor RSA moduli efficiently on a cryptographically relevant quantum computer. "
                "ECDSA P-256 provides equivalent security with a much smaller key. "
                "NIST-approved PQC alternatives (ML-DSA / Dilithium, Falcon) are now available."
            ),
            action=(
                "Issue an ECDSA P-256 or P-384 certificate as an immediate improvement. "
                "For long-term quantum safety, adopt ML-DSA (FIPS 204 / Dilithium3) "
                "or Falcon-512. Hybrid certificates combining classical + PQC are supported "
                "by some CAs already."
            ),
            reference="https://doi.org/10.6028/NIST.FIPS.204",
        ),
    ),

    # ── General / PQC ─────────────────────────────────────────────────────────

    _Rule(
        id="gen_pqc_roadmap",
        condition=lambda r, ctx: not r.is_quantum_safe and r.risk_score >= 4,
        recommendation=Recommendation(
            priority=4,
            category="general",
            title="Develop a Post-Quantum Cryptography (PQC) migration roadmap",
            detail=(
                "NIST completed PQC standardisation in 2024: ML-KEM (FIPS 203), "
                "ML-DSA (FIPS 204), SLH-DSA (FIPS 205). 'Harvest now, decrypt later' "
                "attacks mean sensitive long-lived data encrypted today could be exposed "
                "once quantum computers mature. Organisations should begin migration now."
            ),
            action=(
                "1. Inventory all cryptographic assets (this CBOM is the first step). "
                "2. Prioritise migration of long-lived sensitive data and key infrastructure. "
                "3. Deploy hybrid PQC/classical schemes for key exchange first (lowest risk). "
                "4. Follow CISA/NIST guidance: nist.gov/pqcrypto"
            ),
            reference="https://www.nist.gov/pqcrypto",
        ),
    ),

    _Rule(
        id="gen_certificate_monitoring",
        condition=lambda r, ctx: True,   # always suggest cert monitoring
        recommendation=Recommendation(
            priority=5,
            category="general",
            title="Implement automated certificate expiry monitoring",
            detail=(
                "Certificate expiry is one of the most common and disruptive TLS failures. "
                "Automated monitoring with 30/14/7-day alerting prevents unexpected outages "
                "and ensures certificate hygiene across the entire asset inventory."
            ),
            action=(
                "Use a certificate monitoring tool (e.g. cert-manager for Kubernetes, "
                "Let's Encrypt with auto-renewal, or a commercial monitoring service). "
                "Set alert thresholds at 30 days, 14 days, and 7 days before expiry."
            ),
            reference="https://letsencrypt.org/docs/integration-guide/",
        ),
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_recommendations(
    risk_result: RiskAnalysisResult,
    tls_version: str = "",
    key_exchange: str = "",
    encryption_algorithm: str = "",
    certificate_algorithm: str = "",
) -> RecommendationReport:
    """
    Generate a prioritised list of remediation recommendations for a single
    TLS endpoint, based on its RiskAnalysisResult and raw field values.
    """
    ctx = {
        "tls_version":            tls_version,
        "key_exchange":           key_exchange,
        "encryption_algorithm":   encryption_algorithm,
        "certificate_algorithm":  certificate_algorithm,
    }

    triggered: list[Recommendation] = []
    seen_ids: set[str] = set()

    for rule in _RULES:
        if rule.id in seen_ids:
            continue
        try:
            if rule.condition(risk_result, ctx):
                triggered.append(rule.recommendation)
                seen_ids.add(rule.id)
        except Exception:
            # Never let a rule crash the engine
            pass

    # Sort by priority (ascending = most urgent first)
    triggered.sort(key=lambda rec: rec.priority)

    # Build a human summary
    if risk_result.risk_level == "SAFE":
        summary = (
            f"{risk_result.asset}:{risk_result.port} has a strong TLS configuration. "
            "Continue monitoring for new vulnerabilities and consider PQC migration planning."
        )
    else:
        count = len(triggered)
        summary = (
            f"{risk_result.asset}:{risk_result.port} scored {risk_result.risk_score_display} "
            f"({risk_result.risk_level}). "
            f"{count} recommendation{'s' if count != 1 else ''} identified. "
            "Address CRITICAL and HIGH priority items immediately."
        )

    return RecommendationReport(
        asset=risk_result.asset,
        port=risk_result.port,
        risk_score=risk_result.risk_score,
        risk_level=risk_result.risk_level,
        is_quantum_safe=risk_result.is_quantum_safe,
        recommendations=triggered,
        summary=summary,
    )


def generate_recommendations_batch(
    risk_results: list[RiskAnalysisResult],
    cbom_records: list[dict],
) -> list[RecommendationReport]:
    """
    Generate recommendations for a batch of risk results, matched to their
    CBOM records for raw field access.
    """
    # Build a lookup: (asset, port) → cbom_record
    record_map: dict[tuple[str, int], dict] = {
        (r.get("asset", ""), int(r.get("port", 0))): r
        for r in cbom_records
    }

    reports: list[RecommendationReport] = []
    for result in risk_results:
        rec = record_map.get((result.asset, result.port), {})
        report = generate_recommendations(
            risk_result=result,
            tls_version=rec.get("tls_version", ""),
            key_exchange=rec.get("key_exchange", ""),
            encryption_algorithm=rec.get("encryption_algorithm", ""),
            certificate_algorithm=rec.get("certificate_algorithm", ""),
        )
        reports.append(report)
    return reports