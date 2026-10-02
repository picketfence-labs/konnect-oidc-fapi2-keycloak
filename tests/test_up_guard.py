#!/usr/bin/env python3
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    marker = root / "called"
    fakebin = root / "bin"
    fakebin.mkdir()
    for command in ("docker", "generate-dev-assets.sh", "sync-keycloak-demo-data.py"):
        executable = fakebin / command
        executable.write_text(f"#!/bin/sh\necho called >> '{marker}'\n")
        executable.chmod(0o755)
    environment = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}"}
    result = subprocess.run(
        ["make", "--no-print-directory", "up", "DEV_ASSET_GENERATOR=generate-dev-assets.sh", "DOCKER=docker"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "unavailable until WP5 runtime readiness" in result.stderr
    assert not marker.exists()

print("make up readiness gate: PASS")
