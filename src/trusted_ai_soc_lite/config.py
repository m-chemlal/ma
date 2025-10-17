"""Runtime configuration for the Trusted AI SOC Lite prototype."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


ENV_PREFIX = "TRUSTED_SOC_"


def _get_env(name: str, default: str) -> str:
    return os.getenv(f"{ENV_PREFIX}{name}", default)


def _parse_targets(value: str) -> List[str]:
    targets = [target.strip() for target in value.split(",") if target.strip()]
    return targets or ["127.0.0.1"]


@dataclass
class Settings:
    """Application settings loaded from environment variables when available."""

    data_dir: Path = Path("data")
    nmap_targets: List[str] = field(default_factory=lambda: ["127.0.0.1"])
    nmap_arguments: str = "-sS -sV"
    anomaly_contamination: float = 0.15
    model_state_path: Path = Path("data") / "model_state.json"
    audit_log_path: Path = Path("data") / "audit_log.jsonl"

    @classmethod
    def from_env(cls) -> "Settings":
        defaults = cls()
        data_dir = Path(_get_env("DATA_DIR", str(defaults.data_dir)))
        targets = _parse_targets(_get_env("NMAP_TARGETS", ",".join(defaults.nmap_targets)))
        nmap_arguments = _get_env("NMAP_ARGUMENTS", defaults.nmap_arguments)
        anomaly_contamination = float(_get_env("ANOMALY_CONTAMINATION", str(defaults.anomaly_contamination)))
        model_state_path = Path(_get_env("MODEL_STATE_PATH", str(data_dir / "model_state.json")))
        audit_log_path = Path(_get_env("AUDIT_LOG_PATH", str(data_dir / "audit_log.jsonl")))

        return cls(
            data_dir=data_dir,
            nmap_targets=targets,
            nmap_arguments=nmap_arguments,
            anomaly_contamination=anomaly_contamination,
            model_state_path=model_state_path,
            audit_log_path=audit_log_path,
        )


_CACHED_SETTINGS: Settings | None = None


def get_settings() -> Settings:
    """Return a cached copy of the application settings."""

    global _CACHED_SETTINGS
    if _CACHED_SETTINGS is None:
        _CACHED_SETTINGS = Settings.from_env()
    return _CACHED_SETTINGS


__all__ = ["Settings", "get_settings"]
