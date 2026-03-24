# models.py — Pydantic schemas for Quantum Shield API
# All request/response models are defined here for clear separation of concerns.

import re
from typing import Optional, Any
from pydantic import BaseModel, field_validator, Field


# Regex for validating a bare domain name (no scheme, no path, no port)
_DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}"
    r"[a-zA-Z0-9])?"
    r"\.)+"
    r"[a-zA-Z]{2,}$"
)


# ── Shared request schemas ────────────────────────────────────────────────── #

class DomainRequest(BaseModel):
    """Generic domain-name request. Used by /scan and /discover."""

    domain: str = Field(
        ...,
        min_length=3,
        max_length=253,
        examples=["example.com", "sub.example.co.uk"],
        description="A valid domain name without http/https scheme or path.",
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        value = value.strip().lower()
        if value.startswith(("http://", "https://", "//")):
            raise ValueError(
                "Provide a bare domain name without a URL scheme "
                "(e.g. 'example.com', not 'https://example.com')."
            )
        if "/" in value or "?" in value or "#" in value:
            raise ValueError("Domain must not contain paths, query strings, or fragments.")
        if ":" in value:
            raise ValueError("Domain must not include a port number.")
        if not _DOMAIN_REGEX.match(value):
            raise ValueError(
                f"'{value}' is not a valid domain name. "
                "Expected format: 'example.com' or 'sub.example.co.uk'."
            )
        return value


# Backwards-compat alias
ScanRequest = DomainRequest


# ── Phase 1 — Scan ────────────────────────────────────────────────────────── #

class ScanResponse(BaseModel):
    """Standard response envelope for POST /scan."""
    domain: str = Field(..., description="The sanitised domain that was submitted.")
    status: str = Field(..., description="'success' or 'error'.")
    message: str = Field(..., description="Human-readable status description.")


# ── Phase 2 — Asset discovery ─────────────────────────────────────────────── #

class DiscoveredAsset(BaseModel):
    """A single discovered host with its resolved IP and open ports."""
    host: str = Field(..., description="Fully-qualified subdomain.", examples=["api.example.com"])
    ip: str = Field(..., description="Resolved IPv4 address.", examples=["1.2.3.4"])
    ports: list[int] = Field(default_factory=list, description="Open TCP ports.", examples=[[80, 443]])


class DiscoverResponse(BaseModel):
    """Top-level response envelope for POST /discover."""
    domain: str
    status: str
    total_assets: int
    assets: list[DiscoveredAsset] = Field(default_factory=list)


# ── Phase 3 — TLS scanning ───────────────────────────────────────────────── #

class CertificateInfo(BaseModel):
    """
    Parsed X.509 certificate fields extracted via Python's ssl.getpeercert().

    Note: signature_algorithm requires the 'cryptography' library to extract
    from DER bytes. The stdlib ssl module does not expose it directly.
    """
    subject: Optional[str] = Field(None, description="Certificate subject DN.")
    issuer: Optional[str] = Field(None, description="Certificate issuer DN.")
    serial_number: Optional[str] = Field(None, description="Hex serial number.")
    not_before: Optional[str] = Field(None, description="Certificate valid-from date.")
    not_after: Optional[str] = Field(None, description="Certificate expiry date (ISO-8601 UTC).")
    days_until_expiry: Optional[int] = Field(None, description="Days remaining until expiry. Negative = expired.")
    expiry_status: str = Field("unknown", description="'valid', 'warning', 'critical', 'expired', or 'unknown'.")
    signature_algorithm: Optional[str] = Field(None, description="Signature algorithm (e.g. sha256WithRSAEncryption).")
    subject_alt_names: list[str] = Field(default_factory=list, description="SANs list (e.g. ['DNS:example.com']).")
    version: Optional[int] = Field(None, description="X.509 version (typically 3).")
    ocsp: list[str] = Field(default_factory=list, description="OCSP responder URLs.")
    ca_issuers: list[str] = Field(default_factory=list, description="CA issuer URLs.")


class TLSScanResult(BaseModel):
    """
    Successful TLS handshake result for a single host:port.
    The certificate field may still contain expiry/validation warnings.
    """
    host: str = Field(..., description="Scanned hostname.")
    port: int = Field(..., description="Scanned port number.")
    tls_version: Optional[str] = Field(None, description="Negotiated TLS version (e.g. 'TLSv1.3').")
    cipher: Optional[str] = Field(None, description="Negotiated cipher suite name.")
    cipher_bits: Optional[int] = Field(None, description="Effective key bits for the cipher.")
    tls_version_grade: str = Field("unknown", description="'strong', 'acceptable', 'weak', or 'unknown'.")
    cipher_grade: str = Field("unknown", description="'strong' or 'weak'.")
    certificate: Optional[CertificateInfo] = Field(None, description="Parsed certificate details.")
    certificate_error: Optional[str] = Field(None, description="Set if cert failed CA verification.")
    warnings: list[str] = Field(default_factory=list, description="Security warnings for this result.")


class TLSScanFailure(BaseModel):
    """Records a host:port that could not be connected to at all."""
    host: str
    port: int
    reason: str = Field(..., description="Human-readable failure reason.")


class TLSAssetResult(BaseModel):
    """
    All TLS scan results for a single host (may cover multiple ports).
    Aggregates per-port TLSScanResult and TLSScanFailure entries.
    """
    host: str
    overall_grade: str = Field(
        ...,
        description="Worst-case TLS grade across all ports: 'strong', 'acceptable', 'weak', 'no_tls'."
    )
    scanned_ports: list[int] = Field(default_factory=list, description="All ports that were attempted.")
    results: list[TLSScanResult] = Field(default_factory=list, description="Successful scan results.")
    failures: list[TLSScanFailure] = Field(default_factory=list, description="Ports that failed to connect.")


class TLSScanRequest(BaseModel):
    """Request body for POST /scan-tls."""
    assets: list[DiscoveredAsset] = Field(
        ...,
        min_length=1,
        description="List of assets from /discover to TLS-scan.",
    )


class TLSScanResponse(BaseModel):
    """Top-level response envelope for POST /scan-tls."""
    status: str = Field("success", description="'success' or 'error'.")
    total_hosts_scanned: int = Field(..., description="Number of unique hosts with TLS ports.")
    total_ports_scanned: int = Field(..., description="Total host:port pairs attempted.")
    total_warnings: int = Field(..., description="Aggregated security warning count.")
    results: list[TLSAssetResult] = Field(default_factory=list)


# ── Phase 4 — CBOM models ───────────────────────────────────────────────────
class CBOMRecord(BaseModel):
    """A single CBOM record persisted to the DB. Flexible shape to start."""
    asset: Optional[str] = Field(None, description="Hostname or IP of the asset")
    port: Optional[int] = Field(None, description="Port number")
    tls_version: Optional[str] = Field(None, description="Normalized TLS version")
    cipher_suite: Optional[str] = Field(None, description="Cipher suite string")
    key_exchange: Optional[str] = Field(None)
    encryption_algorithm: Optional[str] = Field(None)
    mac_algorithm: Optional[str] = Field(None)
    certificate_algorithm: Optional[str] = Field(None)
    certificate_signature_algorithm: Optional[str] = Field(None)
    certificate_expiry: Optional[str] = Field(None)
    certificate_subject: Optional[str] = Field(None)
    certificate_issuer: Optional[str] = Field(None)
    certificate_verified: Optional[bool] = Field(None)
    certificate_error: Optional[str] = Field(None)
    raw: Optional[dict] = None


class CBOMResponse(BaseModel):
    status: str = Field("success")
    total_records: int = Field(...)
    records: list[CBOMRecord] = Field(default_factory=list)


class RiskFindingSchema(BaseModel):
    category: str = Field(description="tls_version | key_exchange | encryption | certificate")
    detail: str = Field(description="Human-readable finding description")
    score_contribution: int = Field(description="Points this finding adds to total risk score")
    severity: str = Field(description="SAFE | LOW | MEDIUM | HIGH | CRITICAL")


class RiskAnalysisSchema(BaseModel):
    asset: str
    port: int
    risk_score: int = Field(ge=0, le=10, description="Total risk score 0–10")
    risk_level: str = Field(description="SAFE | LOW | MEDIUM | HIGH | CRITICAL")
    risk_score_display: str = Field(description='e.g. "8/10"')
    findings: list[RiskFindingSchema]
    is_quantum_safe: bool
    quantum_safe_reason: str


class RiskAnalysisBatchResponse(BaseModel):
    status: str = "success"
    domain: str
    total_assets_analyzed: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    safe_count: int
    results: list[RiskAnalysisSchema]


# ---------------------------------------------------------------------------
# Recommendation Engine models
# ---------------------------------------------------------------------------

class RecommendationSchema(BaseModel):
    priority: int = Field(description="1 = most urgent")
    category: str
    title: str
    detail: str
    action: str
    reference: str = ""


class RecommendationReportSchema(BaseModel):
    asset: str
    port: int
    risk_score: int
    risk_level: str
    is_quantum_safe: bool
    recommendations: list[RecommendationSchema]
    summary: str


class RecommendationBatchResponse(BaseModel):
    status: str = "success"
    domain: str
    total_assets: int
    reports: list[RecommendationReportSchema]


# ---------------------------------------------------------------------------
# Combined risk + recommendation (used by /analyze endpoint)
# ---------------------------------------------------------------------------

class AssetAnalysis(BaseModel):
    risk: RiskAnalysisSchema
    recommendations: RecommendationReportSchema


class FullAnalysisResponse(BaseModel):
    status: str = "success"
    domain: str
    total_assets: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    safe_count: int
    quantum_safe_count: int
    analyses: list[AssetAnalysis]


# ── Shared error envelope ─────────────────────────────────────────────────── #

class ErrorDetail(BaseModel):
    """Structured error body returned on 4xx / 5xx responses."""
    status: str = "error"
    message: str
