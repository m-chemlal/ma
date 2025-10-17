import trusted_ai_soc_lite.config as config

import pytest


@pytest.fixture
def isolated_env(monkeypatch, tmp_path):
    data_dir = tmp_path / "soc"
    monkeypatch.setenv("TRUSTED_SOC_DATA_DIR", str(data_dir))
    monkeypatch.setenv("TRUSTED_SOC_MODEL_STATE_PATH", str(data_dir / "model_state.json"))
    monkeypatch.setenv("TRUSTED_SOC_AUDIT_LOG_PATH", str(data_dir / "audit_log.jsonl"))
    config._CACHED_SETTINGS = None
    yield data_dir
    config._CACHED_SETTINGS = None
