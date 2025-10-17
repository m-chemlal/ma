"""Lightweight data structures shared across the Trusted AI SOC Lite components."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Type, TypeVar


def _serialise(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value):
        return _serialise(asdict(value))
    if isinstance(value, list):
        return [_serialise(item) for item in value]
    if isinstance(value, dict):
        return {key: _serialise(val) for key, val in value.items()}
    return value


T = TypeVar("T", bound="Serializable")


class Serializable:
    """Mixin adding JSON (de-)serialisation helpers to dataclasses."""

    def to_dict(self) -> Dict[str, Any]:
        return _serialise(asdict(self))

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), **kwargs)

    @classmethod
    def from_json(cls: Type[T], payload: str) -> T:
        return cls.from_dict(json.loads(payload))

    @classmethod
    def from_dict(cls: Type[T], data: Dict[str, Any]) -> T:
        raise NotImplementedError


@dataclass
class PortFinding(Serializable):
    host: str
    protocol: str
    port: int
    service: str = "unknown"
    product: Optional[str] = None
    cve: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PortFinding":
        return cls(
            host=data.get("host", ""),
            protocol=data.get("protocol", "tcp"),
            port=int(data.get("port", 0)),
            service=data.get("service", "unknown"),
            product=data.get("product"),
            cve=list(data.get("cve", [])),
        )


@dataclass
class ScanObservation(Serializable):
    timestamp: datetime
    scanner: str = "nmap"
    findings: List[PortFinding] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanObservation":
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        findings = [PortFinding.from_dict(item) for item in data.get("findings", [])]
        return cls(
            timestamp=timestamp if isinstance(timestamp, datetime) else datetime.utcnow(),
            scanner=data.get("scanner", "nmap"),
            findings=findings,
        )


@dataclass
class AnomalyInsight(Serializable):
    feature: str
    contribution: float
    description: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnomalyInsight":
        return cls(
            feature=data.get("feature", ""),
            contribution=float(data.get("contribution", 0.0)),
            description=data.get("description", ""),
        )


@dataclass
class AnalysisResult(Serializable):
    observation: ScanObservation
    risk_score: float
    anomaly_flag: bool
    anomaly_reason: str
    insights: List[AnomalyInsight] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisResult":
        observation = ScanObservation.from_dict(data.get("observation", {}))
        insights = [AnomalyInsight.from_dict(item) for item in data.get("insights", [])]
        return cls(
            observation=observation,
            risk_score=float(data.get("risk_score", 0.0)),
            anomaly_flag=bool(data.get("anomaly_flag", False)),
            anomaly_reason=data.get("anomaly_reason", ""),
            insights=insights,
        )


@dataclass
class AlertRecord(Serializable):
    id: str
    generated_at: datetime
    severity: str
    title: str
    description: str
    related_ip: Optional[str] = None
    recommended_action: Optional[str] = None
    analysis: AnalysisResult = field(default_factory=lambda: AnalysisResult.from_dict({}))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AlertRecord":
        generated_at = data.get("generated_at")
        if isinstance(generated_at, str):
            generated_at = datetime.fromisoformat(generated_at)
        analysis = AnalysisResult.from_dict(data.get("analysis", {}))
        return cls(
            id=data.get("id", ""),
            generated_at=generated_at if isinstance(generated_at, datetime) else datetime.utcnow(),
            severity=data.get("severity", "low"),
            title=data.get("title", ""),
            description=data.get("description", ""),
            related_ip=data.get("related_ip"),
            recommended_action=data.get("recommended_action"),
            analysis=analysis,
        )


@dataclass
class AuditEntry(Serializable):
    timestamp: datetime
    actor: str
    action: str
    context: Dict[str, str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        context = {str(k): str(v) for k, v in data.get("context", {}).items()}
        return cls(
            timestamp=timestamp if isinstance(timestamp, datetime) else datetime.utcnow(),
            actor=data.get("actor", ""),
            action=data.get("action", ""),
            context=context,
        )


__all__ = [
    "Serializable",
    "PortFinding",
    "ScanObservation",
    "AnomalyInsight",
    "AnalysisResult",
    "AlertRecord",
    "AuditEntry",
]
