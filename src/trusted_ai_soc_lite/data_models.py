"""Pydantic models shared across the Trusted AI SOC Lite components."""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class PortFinding(BaseModel):
    host: str
    protocol: str
    port: int
    service: str = "unknown"
    product: Optional[str] = None
    cve: List[str] = Field(default_factory=list, description="Potential CVE identifiers mapped to the service.")


class ScanObservation(BaseModel):
    timestamp: datetime
    scanner: str = "nmap"
    findings: List[PortFinding]


class AnomalyInsight(BaseModel):
    feature: str
    contribution: float
    description: str


class AnalysisResult(BaseModel):
    observation: ScanObservation
    risk_score: float
    anomaly_flag: bool
    anomaly_reason: str
    insights: List[AnomalyInsight] = Field(default_factory=list)


class AlertRecord(BaseModel):
    id: str
    generated_at: datetime
    severity: str
    title: str
    description: str
    related_ip: Optional[str] = None
    recommended_action: Optional[str] = None
    analysis: AnalysisResult


class AuditEntry(BaseModel):
    timestamp: datetime
    actor: str
    action: str
    context: Dict[str, str]


__all__ = [
    "PortFinding",
    "ScanObservation",
    "AnomalyInsight",
    "AnalysisResult",
    "AlertRecord",
    "AuditEntry",
]
