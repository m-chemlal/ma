"""Command line entry point to execute a single SOC pipeline cycle."""
from __future__ import annotations

import json

from .pipeline import run_pipeline_cycle


def main() -> None:
    alert = run_pipeline_cycle()
    print(json.dumps(json.loads(alert.to_json()), indent=2))


if __name__ == "__main__":  # pragma: no cover - CLI entry
    main()
