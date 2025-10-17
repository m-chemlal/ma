"""Explainability helpers for the Trusted AI SOC Lite anomaly model."""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence, TYPE_CHECKING

from ..data_models import AnomalyInsight

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .engine import FeatureVector


_DESCRIPTIONS: Dict[str, str] = {
    "total_ports": "Nombre total de ports découverts lors du scan.",
    "unique_services": "Diversité des services exposés sur les hôtes.",
    "high_risk": "Nombre de services associés à des CVE critiques.",
    "open_critical_ports": "Ports sensibles (SSH, HTTP, HTTPS, RDP, MySQL) détectés.",
    "average_port": "Moyenne des ports ouverts utilisée comme proxy de maturité.",
}


def _normalised(values: Sequence[float]) -> List[float]:
    total = sum(abs(value) for value in values)
    if total == 0:
        return [0.0 for _ in values]
    return [abs(value) / total for value in values]


def build_insights(
    feature_vector: "FeatureVector",
    baseline: Optional[Sequence[float]] = None,
) -> List[AnomalyInsight]:
    values = feature_vector.values
    feature_names = feature_vector.feature_names

    if baseline and len(baseline) == len(values):
        contributions = [value - reference for value, reference in zip(values, baseline)]
    else:
        contributions = _normalised(values)

    insights: List[AnomalyInsight] = []
    for feature, contribution in zip(feature_names, contributions):
        description = _DESCRIPTIONS.get(feature, feature)
        insights.append(
            AnomalyInsight(
                feature=feature,
                contribution=float(contribution),
                description=description,
            )
        )

    return sorted(insights, key=lambda insight: abs(insight.contribution), reverse=True)


__all__ = ["build_insights"]
