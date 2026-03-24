"""
Additional Pydantic v2 models for the Quantum Risk Analyzer and
Recommendation Engine. Add these to models.py (or import from here).
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Risk Analyzer models
# ---------------------------------------------------------------------------

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