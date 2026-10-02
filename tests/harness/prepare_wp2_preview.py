#!/usr/bin/env python3
"""Create fresh local Keycloak fixture material under an ignored directory."""

import argparse
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / ".generated/wp2-preview"


def prepare(destination: Path) -> Path:
    destination = destination.absolute()
    generated_root = ROOT / ".generated"
    if generated_root.is_symlink():
        raise RuntimeError("refusing to create WP2 preview assets through a .generated symlink")
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("refusing to reuse an existing WP2 preview directory")
    os.umask(0o077)
    destination.mkdir(mode=0o700, parents=True)
    pki = destination / "pki"
    realm_import = destination / "realm-import"
    pki.mkdir(mode=0o700)
    realm_import.mkdir(mode=0o700)

    try:
        subprocess.run(
            ["python3", str(ROOT / "scripts/generate-pki.py"), str(pki)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        route_b_key = pki / "route-b-pkj.key"
        with route_b_key.open("xb") as output:
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"],
                check=True,
                stdout=output,
                stderr=subprocess.DEVNULL,
            )
        route_b_key.chmod(0o600)
        route_b_public_key = pki / "route-b-pkj.pub"
        with route_b_public_key.open("xb") as output:
            subprocess.run(
                ["openssl", "pkey", "-in", str(route_b_key), "-pubout"],
                check=True,
                stdout=output,
                stderr=subprocess.DEVNULL,
            )
        route_b_public_key.chmod(0o600)

        bootstrap_password = secrets.token_urlsafe(32)
        bootstrap_env = destination / "bootstrap.env"
        bootstrap_env.write_text(
            "KC_BOOTSTRAP_ADMIN_USERNAME=wp2-preview-admin\n"
            f"KC_BOOTSTRAP_ADMIN_PASSWORD={bootstrap_password}\n"
        )
        bootstrap_env.chmod(0o600)

        sales_password = secrets.token_urlsafe(32)
        engineering_password = secrets.token_urlsafe(32)
        accounts_file = destination / "accounts.env"
        accounts_file.write_text(
            "WP2_SALES_USERNAME=sales.user@fapi-demo.invalid\n"
            f"WP2_SALES_PASSWORD={sales_password}\n"
            "WP2_ENGINEERING_USERNAME=engineering.user@fapi-demo.invalid\n"
            f"WP2_ENGINEERING_PASSWORD={engineering_password}\n"
        )
        accounts_file.chmod(0o600)
        environment = {
            **os.environ,
            "SALES_PASSWORD": sales_password,
            "ENGINEERING_PASSWORD": engineering_password,
            "KEYCLOAK_REFRESH_TOKEN_ROTATION": "true",
        }
        realm_file = realm_import / "fapi-demo-realm.json"
        subprocess.run(
            [
                "python3",
                str(ROOT / "scripts/render-keycloak-realm.py"),
                str(ROOT / "keycloak/realm-template.json"),
                str(realm_file),
                str(route_b_public_key),
            ],
            check=True,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        realm_file.chmod(0o600)
        return destination
    except (OSError, subprocess.CalledProcessError) as error:
        shutil.rmtree(destination, ignore_errors=True)
        raise RuntimeError(
            f"WP2 preview preparation failed (child status {getattr(error, 'returncode', 'unavailable')})"
        ) from None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-create-isolated-preview-assets", action="store_true")
    args = parser.parse_args()
    if not args.allow_create_isolated_preview_assets:
        parser.error("pass --allow-create-isolated-preview-assets to create fresh local fixture assets; this does not start a runtime")
    try:
        destination = prepare(DEFAULT_OUTPUT)
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(f"Prepared fresh isolated WP2 preview assets under {destination}")
    print("Secret values and private keys were not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
