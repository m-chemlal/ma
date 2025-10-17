"""Automated response actions for the SOC prototype."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict

from ..config import get_settings
from ..data_models import AlertRecord, AuditEntry
from ..audit.logger import append_audit_entry


def _write_action_snapshot(alert: AlertRecord, action: str, payload: Dict[str, str]) -> None:
    settings = get_settings()
    data_dir = settings.data_dir / "responses"
    data_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = data_dir / f"{alert.id}_{action}.json"
    snapshot_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def block_ip(alert: AlertRecord) -> None:
    """Simulate a network level block for the offending IP address."""
    if not alert.related_ip:
        return

    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": "block_ip",
        "ip": alert.related_ip,
    }
    _write_action_snapshot(alert, "block", payload)
    append_audit_entry(
        AuditEntry(
            timestamp=datetime.utcnow(),
            actor="automation",
            action="block_ip",
            context={"ip": alert.related_ip, "alert_id": alert.id},
        )
    )


def send_email(alert: AlertRecord) -> None:
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": "send_email",
        "subject": alert.title,
        "severity": alert.severity,
    }
    _write_action_snapshot(alert, "email", payload)
    append_audit_entry(
        AuditEntry(
            timestamp=datetime.utcnow(),
            actor="automation",
            action="send_email",
            context={"alert_id": alert.id, "subject": alert.title},
        )
    )


def create_ticket(alert: AlertRecord) -> None:
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": "create_ticket",
        "title": alert.title,
    }
    _write_action_snapshot(alert, "ticket", payload)
    append_audit_entry(
        AuditEntry(
            timestamp=datetime.utcnow(),
            actor="automation",
            action="create_ticket",
            context={"alert_id": alert.id, "title": alert.title},
        )
    )


__all__ = ["block_ip", "send_email", "create_ticket"]
