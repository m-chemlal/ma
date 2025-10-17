"""Streamlit dashboard showcasing the Trusted AI SOC Lite telemetry."""
from __future__ import annotations

import json
from datetime import datetime
from typing import List, Tuple

import pandas as pd
import streamlit as st

from ..audit.logger import load_audit_entries
from ..config import get_settings
from ..data_models import AlertRecord, AnalysisResult

DATA_DIR = get_settings().data_dir
ALERTS_DIR = DATA_DIR / "alerts"
SCANS_DIR = DATA_DIR / "scans"


@st.cache_data(show_spinner=False)
def _load_alerts(limit: int = 10) -> List[AlertRecord]:
    if not ALERTS_DIR.exists():
        return []

    alerts = []
    for path in sorted(ALERTS_DIR.glob("*.json"), reverse=True)[:limit]:
        alerts.append(AlertRecord.parse_file(path))
    return alerts


@st.cache_data(show_spinner=False)
def _load_recent_scans(limit: int = 5) -> List[Tuple[datetime, int]]:
    if not SCANS_DIR.exists():
        return []
    scans = []
    for path in sorted(SCANS_DIR.glob("scan_*.json"), reverse=True)[:limit]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        scans.append((datetime.fromisoformat(payload["timestamp"]), len(payload["findings"])))
    scans.sort()
    return scans


def _ensure_directories() -> None:
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    SCANS_DIR.mkdir(parents=True, exist_ok=True)


def _render_header(total_vuln: int, high: int, medium: int) -> None:
    st.markdown(
        """
        <style>
        .metric-card {
            background: #111827;
            padding: 1.5rem;
            border-radius: 1rem;
            color: #F9FAFB;
        }
        .metric-title {
            font-size: 0.9rem;
            text-transform: uppercase;
            opacity: 0.7;
            margin-bottom: 0.5rem;
        }
        .metric-value {
            font-size: 2.5rem;
            font-weight: 700;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("# TRUSTED AI SOC LITE")
    st.markdown("#### Tableau de bord des alertes autonomes")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(
            f"""
            <div class="metric-card">
              <div class="metric-title">Vulnerabilités détectées</div>
              <div class="metric-value">{total_vuln}</div>
              <div>High: {high} &nbsp;&nbsp; Medium: {medium}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            """
            <div class="metric-card">
              <div class="metric-title">AI Analysis</div>
              <div class="metric-value">Explainable</div>
              <div>Isolation Forest + SHAP/LIME fallback</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            """
            <div class="metric-card">
              <div class="metric-title">Recent Scans</div>
              <div class="metric-value">Live</div>
              <div>Mises à jour périodiques</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def _render_alerts(alerts: List[AlertRecord]) -> None:
    st.subheader("Real-Time Alerts")
    if not alerts:
        st.info("Aucune alerte pour le moment.")
        return

    rows = []
    for alert in alerts:
        rows.append(
            {
                "Time": alert.generated_at.strftime("%H:%M:%S"),
                "Severity": alert.severity.title(),
                "Title": alert.title,
                "Risk": f"{alert.analysis.risk_score:.1f}",
            }
        )

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)


def _render_insights(latest_analysis: AnalysisResult | None) -> None:
    st.subheader("AI Insights")
    if not latest_analysis:
        st.info("En attente de la première analyse.")
        return

    for insight in latest_analysis.insights:
        st.progress(min(1.0, abs(insight.contribution)), text=f"{insight.feature} | {insight.description}")


def _render_recent_scans(scans: List[Tuple[datetime, int]]) -> None:
    st.subheader("Recent Scans")
    if not scans:
        st.warning("Aucun scan historisé.")
        return
    timestamps = [scan[0] for scan in scans]
    open_ports = [scan[1] for scan in scans]
    chart_data = pd.DataFrame({"timestamp": timestamps, "open_ports": open_ports}).set_index("timestamp")
    st.line_chart(chart_data)


def _render_automations(alerts: List[AlertRecord]) -> None:
    st.subheader("Automated Actions")
    if not alerts:
        st.info("Aucune action effectuée.")
        return

    recent_actions = []
    for alert in alerts:
        recent_actions.append((alert.generated_at.strftime("%H:%M:%S"), "blocked", alert.related_ip or "unknown"))
        recent_actions.append((alert.generated_at.strftime("%H:%M:%S"), "ticket created", alert.id))
        recent_actions.append((alert.generated_at.strftime("%H:%M:%S"), "email sent", alert.title))

    action_df = pd.DataFrame(recent_actions, columns=["Time", "Action", "Details"])
    st.dataframe(action_df, use_container_width=True, hide_index=True)


def _render_audit_log() -> None:
    st.subheader("Audit Log")
    entries = list(load_audit_entries(limit=15))
    if not entries:
        st.info("Aucun évènement d'audit pour le moment.")
        return

    log_rows = []
    for entry in entries:
        log_rows.append(
            {
                "Time": entry.timestamp.strftime("%H:%M:%S"),
                "Actor": entry.actor,
                "Action": entry.action,
                "Context": json.dumps(entry.context),
            }
        )
    st.dataframe(pd.DataFrame(log_rows), use_container_width=True, hide_index=True)


def main() -> None:
    _ensure_directories()
    alerts = _load_alerts()
    recent_scans = _load_recent_scans()
    latest_analysis = alerts[0].analysis if alerts else None

    total_vuln = sum(len(alert.analysis.observation.findings) for alert in alerts)
    high = sum(1 for alert in alerts if alert.severity in {"high", "critical"})
    medium = sum(1 for alert in alerts if alert.severity == "medium")

    _render_header(total_vuln, high, medium)

    col1, col2 = st.columns((2, 1))
    with col1:
        _render_alerts(alerts)
        _render_recent_scans(recent_scans)
    with col2:
        _render_insights(latest_analysis)
        _render_automations(alerts)
        _render_audit_log()


if __name__ == "__main__":
    main()
