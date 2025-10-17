"""Explainability helpers for the Trusted AI SOC Lite anomaly model."""
from __future__ import annotations

from typing import Dict, List

import numpy as np

from ..data_models import AnomalyInsight

_DESCRIPTIONS: Dict[str, str] = {
    "total_ports": "Nombre total de ports découverts lors du scan.",
    "unique_services": "Diversité des services exposés sur les hôtes.",
    "high_risk": "Nombre de services associés à des CVE critiques.",
    "open_critical_ports": "Ports sensibles (SSH, HTTP, HTTPS, RDP, MySQL) détectés.",
    "average_port": "Moyenne des ports ouverts utilisée comme proxy de maturité.",
}


def _fallback_contributions(values: np.ndarray, feature_names: List[str]) -> np.ndarray:
    # Normalise the feature vector and use it as relative importance when SHAP is not available.
    if np.allclose(values, 0):
        return np.zeros_like(values)
    normalised = values / (np.linalg.norm(values) + 1e-9)
    return normalised


def build_insights(model, feature_vector) -> List[AnomalyInsight]:  # pragma: no cover - requires heavy deps
    values = feature_vector.values.reshape(1, -1)
    feature_names = feature_vector.feature_names
    contributions = None

    try:
        import shap  # type: ignore

        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(values)
        if isinstance(shap_values, list):
            shap_values = shap_values[0]
        contributions = shap_values[0]
    except Exception:
        contributions = _fallback_contributions(feature_vector.values, feature_names)

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
