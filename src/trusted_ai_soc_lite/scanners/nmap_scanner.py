"""Wrapper around Nmap scans with graceful degradation when Nmap is unavailable."""
from __future__ import annotations

import json
import random
from datetime import datetime
from pathlib import Path
from typing import Iterable, List

from ..config import get_settings
from ..data_models import PortFinding, ScanObservation

# Minimal mapping between well known services and public CVE identifiers.
SERVICE_TO_CVES = {
    "ssh": ["CVE-2023-38408", "CVE-2018-15473"],
    "http": ["CVE-2021-41773", "CVE-2022-23943"],
    "https": ["CVE-2022-0778"],
    "mysql": ["CVE-2021-35604"],
    "rdp": ["CVE-2019-0708"],
}


def _build_findings_from_nmap(scanner: "nmap.PortScanner") -> List[PortFinding]:
    findings: List[PortFinding] = []
    for host in scanner.all_hosts():
        protocols: Iterable[str] = scanner[host].all_protocols()
        for proto in protocols:
            ports = scanner[host][proto].keys()
            for port in ports:
                service = scanner[host][proto][port].get("name", "unknown")
                product = scanner[host][proto][port].get("product")
                findings.append(
                    PortFinding(
                        host=host,
                        protocol=proto,
                        port=port,
                        service=service,
                        product=product,
                        cve=SERVICE_TO_CVES.get(service, []),
                    )
                )
    return findings


def _simulate_findings(targets: Iterable[str]) -> List[PortFinding]:
    services = ["ssh", "http", "https", "rdp", "unknown"]
    findings: List[PortFinding] = []
    for target in targets:
        for port in random.sample(range(20, 1024), k=3):
            service = random.choice(services)
            findings.append(
                PortFinding(
                    host=target,
                    protocol="tcp",
                    port=port,
                    service=service,
                    product="simulated",
                    cve=SERVICE_TO_CVES.get(service, []),
                )
            )
    return findings


def run_scan(output_dir: Path | None = None) -> ScanObservation:
    """Execute an Nmap scan and returns the parsed observation."""

    settings = get_settings()
    targets = settings.nmap_targets
    try:
        import nmap  # type: ignore

        scanner = nmap.PortScanner()
        scanner.scan(hosts=" ".join(targets), arguments=settings.nmap_arguments)
        findings = _build_findings_from_nmap(scanner)
    except Exception as exc:  # pragma: no cover - environment specific
        # Fall back to a deterministic pseudo random dataset so the pipeline keeps working.
        random.seed(42)
        findings = _simulate_findings(targets)
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            failure_path = output_dir / "nmap_failure.json"
            failure_path.write_text(json.dumps({"error": str(exc)}, indent=2), encoding="utf-8")

    observation = ScanObservation(timestamp=datetime.utcnow(), findings=findings)

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        snapshot_path = output_dir / f"scan_{observation.timestamp.isoformat()}.json"
        snapshot_path.write_text(observation.json(indent=2), encoding="utf-8")

    return observation


__all__ = ["run_scan"]
