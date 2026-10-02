#!/usr/bin/env python3
"""Start only the dedicated WP2 Keycloak Compose project after approval."""

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROJECT = "wp2-isolated-keycloak"
VOLUME = "wp2-isolated-keycloak-data"
COMPOSE_FILE = ROOT / "tests/harness/docker-compose.wp2.yml"
PREVIEW = ROOT / ".generated/wp2-preview"


def run(command):
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-start-isolated-keycloak", action="store_true")
    args = parser.parse_args()
    if not args.allow_start_isolated_keycloak:
        parser.error("starting the isolated Docker service requires separate approval")
    required = (
        PREVIEW / "bootstrap.env",
        PREVIEW / "realm-import/fapi-demo-realm.json",
        PREVIEW / "pki/ca.crt",
        PREVIEW / "pki/keycloak.crt",
        PREVIEW / "pki/keycloak.key",
    )
    if PREVIEW.is_symlink() or (PREVIEW / "pki").is_symlink() or (PREVIEW / "realm-import").is_symlink() or any(
        not path.is_file() or path.is_symlink() for path in required
    ):
        print("fresh isolated preview assets are incomplete", file=sys.stderr)
        return 1
    daemon = run(["docker", "info", "--format", "{{.ServerVersion}}"])
    if daemon.returncode != 0:
        print("Docker daemon is unavailable", file=sys.stderr)
        return 1
    containers = run([
        "docker", "ps", "--all", "--quiet",
        "--filter", f"label=com.docker.compose.project={PROJECT}",
    ])
    if containers.returncode != 0:
        print("could not inspect the isolated Compose project", file=sys.stderr)
        return 1
    if containers.stdout.strip():
        print("refusing to reuse existing containers for the WP2 preview project", file=sys.stderr)
        return 1
    volume = run([
        "docker", "volume", "ls",
        "--filter", f"name={VOLUME}",
        "--format", "{{.Name}}",
    ])
    if volume.returncode != 0:
        print("could not verify that the isolated preview volume is absent", file=sys.stderr)
        return 1
    if VOLUME in {line.strip() for line in volume.stdout.splitlines()}:
        print("refusing to reuse an existing WP2 preview volume", file=sys.stderr)
        return 1

    command = [
        "docker", "compose",
        "--project-directory", str(ROOT),
        "--project-name", PROJECT,
        "-f", str(COMPOSE_FILE),
        "up", "--no-build", "-d", "keycloak",
    ]
    result = subprocess.run(command, cwd=ROOT)
    if result.returncode != 0:
        print("isolated Keycloak Compose start failed", file=sys.stderr)
        return result.returncode
    print("Started the isolated Keycloak service on 127.0.0.1:18444.")
    print("No other Compose project was targeted. Review the approved cleanup command in tests/harness/README.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
