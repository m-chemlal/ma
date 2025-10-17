"""Structured audit logging for all automated decisions."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..config import get_settings
from ..data_models import AuditEntry


def append_audit_entry(entry: AuditEntry) -> None:
    settings = get_settings()
    path = settings.audit_log_path
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(entry.json())
        fh.write("\n")


def load_audit_entries(limit: int | None = None) -> Iterable[AuditEntry]:
    settings = get_settings()
    path = settings.audit_log_path
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as fh:
        lines = fh.readlines()
    if limit:
        lines = lines[-limit:]
    return [AuditEntry.parse_raw(line) for line in lines]


__all__ = ["append_audit_entry", "load_audit_entries"]
