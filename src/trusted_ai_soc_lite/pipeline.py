"""High-level orchestration to run the Trusted AI SOC Lite pipeline end-to-end."""
from __future__ import annotations

import uuid
from datetime import datetime

from .ai.engine import analyze_scan
from .audit.logger import append_audit_entry
from .config import get_settings
from .data_models import AlertRecord, AnalysisResult, AuditEntry
from .responder import actions
from .scanners.nmap_scanner import run_scan


def _severity_from_score(score: float) -> str:
    if score >= 7:
        return "critical"
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def _build_alert(analysis: AnalysisResult) -> AlertRecord:
    severity = _severity_from_score(analysis.risk_score)
    related_ip = analysis.observation.findings[0].host if analysis.observation.findings else None
    title = f"{severity.title()} risk exposure detected"
    description = analysis.anomaly_reason
    return AlertRecord(
        id=str(uuid.uuid4()),
        generated_at=datetime.utcnow(),
        severity=severity,
        title=title,
        description=description,
        related_ip=related_ip,
        recommended_action="Review automated response and validate mitigation",
        analysis=analysis,
    )


def run_pipeline_cycle() -> AlertRecord:
    settings = get_settings()
    observation = run_scan(output_dir=settings.data_dir / "scans")
    analysis = analyze_scan(observation)
    alert = _build_alert(analysis)

    alerts_dir = settings.data_dir / "alerts"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    alert_path = alerts_dir / f"{alert.id}.json"
    alert_path.write_text(alert.json(indent=2), encoding="utf-8")

    append_audit_entry(
        AuditEntry(
            timestamp=datetime.utcnow(),
            actor="ai_engine",
            action="generated_alert",
            context={"alert_id": alert.id, "severity": alert.severity},
        )
    )

    # Automated responses triggered for medium+ severity alerts.
    if alert.severity in {"medium", "high", "critical"}:
        actions.block_ip(alert)
        actions.send_email(alert)
        actions.create_ticket(alert)

    return alert


__all__ = ["run_pipeline_cycle"]
