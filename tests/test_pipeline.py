from pathlib import Path
import json

from trusted_ai_soc_lite.pipeline import run_pipeline_cycle
from trusted_ai_soc_lite.config import get_settings


def test_pipeline_cycle_creates_alert_and_artifacts(isolated_env):
    alert = run_pipeline_cycle()

    alerts_dir = isolated_env / "alerts"
    scans_dir = isolated_env / "scans"
    responses_dir = isolated_env / "responses"
    audit_log = isolated_env / "audit_log.jsonl"

    assert alerts_dir.exists()
    assert any(alerts_dir.glob("*.json"))
    assert scans_dir.exists()
    assert any(scans_dir.glob("*.json"))
    assert audit_log.exists()

    response_files = list(responses_dir.glob("*.json")) if responses_dir.exists() else []
    if alert.severity in {"medium", "high", "critical"}:
        assert len(response_files) == 3
    else:
        assert not response_files


def test_pipeline_learns_baseline_across_runs(isolated_env):
    first = run_pipeline_cycle()
    second = run_pipeline_cycle()

    assert first.analysis.anomaly_flag is False
    assert second.analysis.anomaly_flag is False

    settings = get_settings()
    model_state = json.loads(Path(settings.model_state_path).read_text())
    assert len(model_state["vectors"]) == 2
    assert model_state["feature_names"]
