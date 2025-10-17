"""AI analysis pipeline combining clustering, anomaly detection and scoring."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest

from ..config import get_settings
from ..data_models import AnalysisResult, ScanObservation
from .xai import build_insights


@dataclass
class FeatureVector:
    values: np.ndarray
    feature_names: List[str]


def _extract_features(observation: ScanObservation) -> FeatureVector:
    counts_by_service = {}
    critical_ports = {22, 80, 443, 3389, 3306}
    total_ports = len(observation.findings)
    high_risk = 0
    open_critical_ports = 0

    for finding in observation.findings:
        counts_by_service[finding.service] = counts_by_service.get(finding.service, 0) + 1
        if finding.cve:
            high_risk += 1
        if finding.port in critical_ports:
            open_critical_ports += 1

    avg_port = np.mean([f.port for f in observation.findings]) if observation.findings else 0
    unique_services = len(counts_by_service)

    features = np.array(
        [
            total_ports,
            unique_services,
            high_risk,
            open_critical_ports,
            avg_port,
        ],
        dtype=float,
    )

    return FeatureVector(
        values=features,
        feature_names=[
            "total_ports",
            "unique_services",
            "high_risk",
            "open_critical_ports",
            "average_port",
        ],
    )


def _load_historical_features(path: Path) -> Tuple[np.ndarray, List[str]]:
    if not path.exists():
        return np.empty((0, 5)), []

    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)

    return np.array(payload["vectors"], dtype=float), payload["feature_names"]


def _save_historical_features(path: Path, vectors: np.ndarray, feature_names: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"vectors": vectors.tolist(), "feature_names": feature_names}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def analyze_scan(observation: ScanObservation) -> AnalysisResult:
    settings = get_settings()
    feature_vector = _extract_features(observation)

    historical_vectors, feature_names = _load_historical_features(settings.model_state_path)
    if historical_vectors.size == 0:
        model = IsolationForest(contamination=settings.anomaly_contamination, random_state=42)
        model.fit(feature_vector.values.reshape(1, -1))
        historical_vectors = feature_vector.values.reshape(1, -1)
        feature_names = feature_vector.feature_names
    else:
        model = IsolationForest(contamination=settings.anomaly_contamination, random_state=42)
        model.fit(historical_vectors)
        historical_vectors = np.vstack([historical_vectors, feature_vector.values])

    _save_historical_features(settings.model_state_path, historical_vectors, feature_vector.feature_names)

    anomaly_score = model.decision_function(feature_vector.values.reshape(1, -1))[0]
    anomaly_flag = anomaly_score < 0

    risk_score = max(0.0, min(10.0, 5 - anomaly_score * 10))
    anomaly_reason = "Anomalous network exposure detected" if anomaly_flag else "Within learned baseline"

    insights = build_insights(model, feature_vector)

    return AnalysisResult(
        observation=observation,
        risk_score=float(risk_score),
        anomaly_flag=anomaly_flag,
        anomaly_reason=anomaly_reason,
        insights=insights,
    )


__all__ = ["analyze_scan"]
