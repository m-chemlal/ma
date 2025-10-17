"""AI analysis pipeline relying on lightweight statistical heuristics."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, pstdev
from typing import List, Sequence, Tuple

from ..config import get_settings
from ..data_models import AnalysisResult, ScanObservation
from .xai import build_insights


@dataclass
class FeatureVector:
    values: List[float]
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

    avg_port = sum(f.port for f in observation.findings) / total_ports if total_ports else 0.0
    unique_services = len(counts_by_service)

    features = [
        float(total_ports),
        float(unique_services),
        float(high_risk),
        float(open_critical_ports),
        float(avg_port),
    ]

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


def _load_historical_features(path: Path) -> Tuple[List[List[float]], List[str]]:
    if not path.exists():
        return [], []

    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)

    return [list(map(float, vector)) for vector in payload.get("vectors", [])], payload.get("feature_names", [])


def _save_historical_features(path: Path, vectors: Sequence[Sequence[float]], feature_names: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"vectors": [list(vector) for vector in vectors], "feature_names": list(feature_names)}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _compute_baseline_stats(vectors: Sequence[Sequence[float]]) -> Tuple[List[float], List[float]]:
    transposed = list(zip(*vectors)) if vectors else []
    means: List[float] = []
    deviations: List[float] = []
    for column in transposed:
        values = [float(v) for v in column]
        means.append(mean(values))
        deviations.append(pstdev(values) if len(values) > 1 else 0.0)
    return means, deviations


def _avg_z_score(values: Sequence[float], means: Sequence[float], deviations: Sequence[float]) -> float:
    if not values:
        return 0.0
    z_scores: List[float] = []
    for value, mu, sigma in zip(values, means, deviations):
        if sigma == 0:
            z_scores.append(0.0)
        else:
            z_scores.append(abs(value - mu) / sigma)
    return sum(z_scores) / len(z_scores) if z_scores else 0.0


def _heuristic_risk(values: Sequence[float], baseline_mean: Sequence[float] | None, z_score: float) -> float:
    total_ports, unique_services, high_risk, open_critical_ports, avg_port = values
    # Base risk derived from direct findings.
    base = high_risk * 2.5 + open_critical_ports * 1.5 + total_ports * 0.25
    # High average ports are usually sensitive (database, admin tooling).
    base += max(0.0, (avg_port - 1024) / 200.0)

    if baseline_mean:
        # Penalise significant drifts from the historical baseline.
        drift = sum(abs(v - m) for v, m in zip(values, baseline_mean)) / len(values)
        base += min(4.0, drift * 0.5)

    base += min(4.0, z_score * 1.5)
    return max(0.0, min(10.0, base))


def analyze_scan(observation: ScanObservation) -> AnalysisResult:
    settings = get_settings()
    feature_vector = _extract_features(observation)

    historical_vectors, feature_names = _load_historical_features(settings.model_state_path)
    baseline_means: List[float] | None = None
    baseline_deviations: List[float] | None = None

    if not historical_vectors:
        historical_vectors = [feature_vector.values.copy()]
        feature_names = feature_vector.feature_names
        z_score = 0.0
        anomaly_flag = False
        anomaly_reason = "Baseline established from first observation"
    else:
        if not feature_names:
            feature_names = feature_vector.feature_names
        baseline_means, baseline_deviations = _compute_baseline_stats(historical_vectors)
        z_score = _avg_z_score(feature_vector.values, baseline_means, baseline_deviations)
        anomaly_flag = z_score > 2.5
        anomaly_reason = "Deviation from historical baseline detected" if anomaly_flag else "Within learned baseline"
        historical_vectors = [*historical_vectors, feature_vector.values.copy()]

    _save_historical_features(settings.model_state_path, historical_vectors, feature_vector.feature_names)

    risk_score = _heuristic_risk(
        feature_vector.values,
        baseline_means,
        z_score,
    )

    insights = build_insights(feature_vector, baseline_means)

    return AnalysisResult(
        observation=observation,
        risk_score=float(risk_score),
        anomaly_flag=anomaly_flag,
        anomaly_reason=anomaly_reason,
        insights=insights,
    )


__all__ = ["analyze_scan"]
