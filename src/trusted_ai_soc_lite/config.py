"""Runtime configuration for the Trusted AI SOC Lite prototype."""
from __future__ import annotations

from pathlib import Path
from typing import List

from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables when available."""

    data_dir: Path = Field(default=Path("data"), description="Directory used to persist JSON artefacts.")
    nmap_targets: List[str] = Field(
        default_factory=lambda: ["127.0.0.1"],
        description="CIDR ranges or hosts to scan with Nmap.",
    )
    nmap_arguments: str = Field(
        default="-sS -sV",
        description="Extra command line arguments passed to Nmap when available.",
    )
    anomaly_contamination: float = Field(
        default=0.15,
        description="Expected proportion of anomalies used by the IsolationForest model.",
    )
    model_state_path: Path = Field(
        default=Path("data") / "model_state.json",
        description="Location where the trained AI model metadata is stored.",
    )
    audit_log_path: Path = Field(
        default=Path("data") / "audit_log.jsonl",
        description="Path of the structured audit log file.",
    )

    class Config:
        env_prefix = "TRUSTED_SOC_"


def get_settings() -> Settings:
    """Return a cached copy of the application settings."""
    return Settings()  # type: ignore[call-arg]


__all__ = ["Settings", "get_settings"]
