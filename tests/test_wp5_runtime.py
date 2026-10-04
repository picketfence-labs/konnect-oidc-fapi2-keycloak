"""Offline checks for the third-party runtime declaration and local entry gate."""

import json
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROUTE_A = "754519ff-b0b9-5ed5-94c0-e453d260c6c4"
ROUTE_B = "0f45debe-a3a6-5207-aea3-637227fb96f2"
CONFIG_HASH = "a" * 64
ROUTES = [
    {"route_id": ROUTE_A, "logical_route": "A", "client_id": "third-party-fapi-mtls"},
    {"route_id": ROUTE_B, "logical_route": "B", "client_id": "third-party-fapi-pkj-mtls"},
]


def deck_yaml(path):
    rendered = re.sub(
        r'\$\{\{\s*env\s+"([A-Z0-9_]+)"\s*\}\}',
        lambda match: f"deck-template:{match.group(1)}",
        path.read_text(),
    )
    if "${{" in rendered:
        raise AssertionError(f"unrendered decK template in {path}")
    return yaml.safe_load(rendered)


def state_payload(ready=True):
    workers = []
    for worker_id, pid, epoch in ((0, 5101, "b" * 64), (1, 5102, "c" * 64)):
        workers.append(
            {
                "worker_id": worker_id,
                "pid": pid,
                "generation": "wp5-test-generation",
                "config_hash": CONFIG_HASH,
                "registry_epoch": epoch,
                "wrapper_ready": True,
                "registry_ready": ready,
                "bridge_loaded": True,
                "delegate_ready": True,
                "routes": ROUTES,
            }
        )
    return {
        "generation": "wp5-test-generation",
        "config_hash": CONFIG_HASH,
        "workers": workers,
    }


class ThirdPartyRuntimeTests(unittest.TestCase):
    def test_tcp_forwarder_rejects_non_loopback_or_non_fixed_ports(self):
        path = ROOT / "scripts/wp5-demo-forward.py"
        spec = importlib.util.spec_from_file_location("wp5_demo_forward", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with self.assertRaises(ValueError):
            module.LocalForwarder("0.0.0.0", 8443, "127.0.0.1", 18443)
        with self.assertRaises(ValueError):
            module.LocalForwarder("127.0.0.1", 9443, "127.0.0.1", 18443)

    def test_declarative_state_preserves_foundation_entities_and_fixed_routes(self):
        foundation = deck_yaml(ROOT / "kong/foundation/third-party.yaml")
        state = deck_yaml(ROOT / "kong/third-party-gateway.yaml")
        self.assertEqual(state["certificates"], foundation["certificates"])
        self.assertEqual(state["ca_certificates"], foundation["ca_certificates"])
        self.assertEqual(state["plugins"], foundation["plugins"])
        services = {service["name"]: service for service in state["services"]}
        self.assertEqual(
            set(services), {"third-party-route-a-api", "third-party-route-b-api"}
        )
        self.assertTrue(all(service["port"] == 8443 for service in services.values()))
        api_state = deck_yaml(ROOT / "kong/api-gateway.yaml")
        api_paths = {path for service in api_state["services"]
                     for route in service["routes"] for path in route["paths"]}
        self.assertTrue(all(service["path"] in api_paths for service in services.values()))
        routes = {route["id"] for service in services.values() for route in service["routes"]}
        self.assertEqual(routes, {ROUTE_A, ROUTE_B})
        route_a_plugins = {
            plugin["name"]: plugin for plugin in services["third-party-route-a-api"]["plugins"]
        }
        self.assertEqual(
            route_a_plugins["openid-connect"]["config"]["login_tokens"], ["id_token"]
        )
        route_b = services["third-party-route-b-api"]
        plugins = {plugin["name"]: plugin for plugin in route_b["plugins"]}
        bridge = plugins["fapi-client-auth-bridge"]["config"]
        self.assertEqual(bridge["assertion_delivery"], "transport_delegate")
        self.assertEqual(bridge["assertion_ttl"], 60)
        oidc = plugins["openid-connect"]["config"]
        self.assertEqual(oidc["token_endpoint_auth_method"], "tls_client_auth")
        self.assertEqual(oidc["pushed_authorization_request_endpoint_auth_method"], "private_key_jwt")
        self.assertEqual(oidc["revocation_endpoint_auth_method"], "private_key_jwt")
        self.assertEqual(oidc["login_tokens"], ["id_token"])
        self.assertTrue(oidc["logout_revoke_access_token"])
        self.assertTrue(oidc["logout_revoke_refresh_token"])
        self.assertEqual(oidc["issuer"], "https://localhost:8444/realms/fapi-demo")
        self.assertEqual(
            oidc["token_endpoint"],
            "https://keycloak:8443/realms/fapi-demo/protocol/openid-connect/token",
        )

    def test_compose_keeps_normal_entry_closed_and_tls_material_scoped(self):
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
        third_party = compose["services"]["kong-third-party"]
        api = compose["services"]["kong-api"]
        self.assertEqual(
            third_party["environment"]["KONG_PROXY_LISTEN"],
            "${FAPI_DEMO_PROXY_LISTEN:-off}",
        )
        self.assertIn('test "$$KONG_PLUGINS"', third_party["command"][0])
        self.assertIn("exec /entrypoint.sh kong docker-start", third_party["command"][0])
        self.assertIn("127.0.0.1:18443:8443", third_party["ports"])
        self.assertNotIn("127.0.0.1:8443:8443", third_party["ports"])
        self.assertEqual(
            compose["services"]["ui"]["ports"],
            ["127.0.0.1:3000:80", "127.0.0.1:3443:443"],
        )
        tp_volumes = "\n".join(third_party["volumes"])
        api_volumes = "\n".join(api["volumes"])
        self.assertIn("kong-proxy.crt:/etc/kong/fapi/kong-proxy.crt:ro", tp_volumes)
        self.assertIn("kong-proxy.key:/etc/kong/fapi/kong-proxy.key:ro", tp_volumes)
        self.assertNotIn("kong-proxy.", api_volumes)

    def test_realm_generator_registers_route_b_key_id_and_ps256_provider(self):
        template_path = ROOT / "keycloak/realm-template.json"
        template = json.loads(template_path.read_text())
        route_b = next(c for c in template["clients"] if c["clientId"] == "third-party-fapi-pkj-mtls")
        self.assertEqual(route_b["attributes"]["jwt.credential.kid"], "__ROUTE_B_JWK_KID__")
        provider = template["components"]["org.keycloak.keys.KeyProvider"][0]
        self.assertEqual(provider["providerId"], "rsa-generated")
        self.assertEqual(provider["config"]["algorithm"], ["PS256"])

        with tempfile.TemporaryDirectory() as temporary:
            public_key = Path(temporary) / "public-key.txt"
            output = Path(temporary) / "realm.json"
            public_key.write_text("test-public-key")
            env = {
                "PATH": os.environ["PATH"],
                "SALES_PASSWORD": "test-sales",
                "ENGINEERING_PASSWORD": "test-engineering",
                "DECK_ROUTE_B_JWK_KID": "registered-stock-kid",
                "KEYCLOAK_REFRESH_TOKEN_ROTATION": "true",
            }
            subprocess.run(
                [sys.executable, str(ROOT / "scripts/render-keycloak-realm.py"), str(template_path), str(output), str(public_key)],
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            rendered = json.loads(output.read_text())
            rendered_b = next(c for c in rendered["clients"] if c["clientId"] == "third-party-fapi-pkj-mtls")
            self.assertEqual(rendered_b["attributes"]["jwt.credential.kid"], "registered-stock-kid")

    def test_wait_validator_requires_full_worker_set_and_worker_local_epochs(self):
        script = (ROOT / "scripts/require-wp5-readiness.sh").read_text()
        marker = "validator=\"$(cat <<'PY'\n"
        validator = script.split(marker, 1)[1].split("\nPY\n)\"", 1)[0]
        rows = state_payload()["workers"]
        snapshot = ["G\twp5-test-generation"]
        snapshot.extend(f"P\t{worker['pid']}" for worker in rows)
        snapshot.extend(
            "S\tworker-{}.json\t{}".format(worker["worker_id"], json.dumps(worker))
            for worker in rows
        )
        accepted = subprocess.run(
            [sys.executable, "-c", validator, "wp5-test-generation"],
            input="\n".join(snapshot) + "\n",
            capture_output=True,
            text=True,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        fingerprint, marker_json = accepted.stdout.splitlines()
        self.assertEqual(len(fingerprint), 64)
        marker_value = json.loads(marker_json)
        self.assertEqual(marker_value["generation"], "wp5-test-generation")
        self.assertEqual(
            set(marker_value["workers"][0]),
            {"worker_id", "pid", "registry_epoch"},
        )
        self.assertIs(type(marker_value["workers"][0]["worker_id"]), int)
        self.assertEqual(marker_value["workers"][0]["registry_epoch"], "b" * 64)
        self.assertNotEqual(rows[0]["registry_epoch"], rows[1]["registry_epoch"])

        rows[1]["delegate_ready"] = False
        rejected_snapshot = ["G\twp5-test-generation"]
        rejected_snapshot.extend(f"P\t{worker['pid']}" for worker in rows)
        rejected_snapshot.extend(
            "S\tworker-{}.json\t{}".format(worker["worker_id"], json.dumps(worker))
            for worker in rows
        )
        rejected = subprocess.run(
            [sys.executable, "-c", validator, "wp5-test-generation"],
            input="\n".join(rejected_snapshot) + "\n",
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(rejected.returncode, 0)

    def test_supervisor_gates_entry_and_closes_it_on_readiness_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts"
            scripts.mkdir()
            readiness = scripts / "require-wp5-readiness.sh"
            readiness.write_text((ROOT / "scripts/require-wp5-readiness.sh").read_text())
            readiness.chmod(0o755)
            (scripts / "wp5-demo-forward.py").write_text(
                """#!/usr/bin/env python3
import os, signal, time
from pathlib import Path
log = Path(os.environ['WP5_TEST_LOG'])
def event(value):
    with log.open('a') as stream:
        stream.write(value + '\\n')
def stop(*_):
    event('forward-stopped')
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
event('forward-started')
print('WP5 local TCP forward active', flush=True)
while True:
    time.sleep(0.05)
"""
            )
            fakebin = root / "bin"
            fakebin.mkdir()
            state_path, log_path = root / "state.json", root / "events.log"
            docker_log = root / "docker.log"
            state_path.write_text(json.dumps(state_payload(ready=False)))
            fake_docker = fakebin / "docker"
            fake_docker.write_text(
                """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
state_path = Path(os.environ['WP5_TEST_STATE'])
log_path = Path(os.environ['WP5_TEST_LOG'])
with Path(os.environ['WP5_TEST_DOCKER_LOG']).open('a') as stream:
    stream.write(repr(args) + '\\n')
def log(value):
    with log_path.open('a') as stream:
        stream.write(value + '\\n')
if args and args[0] == 'inspect':
    print('true')
elif args and args[0] == 'compose':
    if 'ps' in args:
        print('a' * 64)
    elif 'up' in args:
        log('ui-started')
    elif 'stop' in args:
        log('stop:' + ','.join(args[args.index('stop') + 1:]))
elif args and args[0] == 'exec':
    command = args[args.index('/bin/sh') + 2]
    state = json.loads(state_path.read_text())
    if 'master_file' in command:
        print('G\\t' + state['generation'])
        for worker in state['workers']:
            print('P\\t' + str(worker['pid']))
            print('S\\tworker-' + str(worker['worker_id']) + '.json\\t' + json.dumps(worker))
    elif 'cat >' in command and 'ready.json' in command:
        marker = json.loads(sys.stdin.read())
        assert marker['generation'] == state['generation']
        log('marker-published')
    elif 'rm -f' in command and 'ready.json' in command:
        log('marker-removed')
    sys.exit(0)
"""
            )
            fake_docker.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{fakebin}:{os.environ['PATH']}",
                "FAPI_DEMO_PROXY_LISTEN": "0.0.0.0:8443 ssl",
                "WP5_TEST_STATE": str(state_path),
                "WP5_TEST_LOG": str(log_path),
                "WP5_TEST_DOCKER_LOG": str(docker_log),
            }
            process = subprocess.Popen(
                [str(readiness), "--supervise", "--timeout", "12", "--interval", "1"],
                cwd=root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                time.sleep(0.25)
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    self.fail(f"supervisor exited before readiness: {stdout} {stderr}")
                events = log_path.read_text().splitlines() if log_path.exists() else []
                self.assertNotIn("marker-published", events)
                self.assertNotIn("forward-started", events)
                self.assertNotIn("ui-started", events)

                state_path.write_text(json.dumps(state_payload(ready=True)))
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    events = log_path.read_text().splitlines() if log_path.exists() else []
                    if "ui-started" in events:
                        break
                    if process.poll() is not None:
                        stdout, stderr = process.communicate()
                        self.fail(f"supervisor exited before opening entry: {stdout} {stderr}; docker={docker_log.read_text() if docker_log.exists() else ''}")
                    time.sleep(0.05)
                else:
                    process.terminate()
                    stdout, stderr = process.communicate(timeout=5)
                    self.fail(f"ready entry did not open: {stdout} {stderr}; docker={docker_log.read_text() if docker_log.exists() else ''}")

                events = log_path.read_text().splitlines()
                self.assertIn("marker-published", events, events)
                self.assertLess(events.index("marker-published"), events.index("forward-started"))
                self.assertLess(events.index("forward-started"), events.index("ui-started"))
                state_path.write_text(json.dumps(state_payload(ready=False)))
                stdout, stderr = process.communicate(timeout=8)
                self.assertNotEqual(process.returncode, 0, stdout)
                self.assertIn("readiness changed", stderr)
                events = log_path.read_text().splitlines()
                last_marker_removal = max(i for i, event in enumerate(events) if event == "marker-removed")
                self.assertLess(last_marker_removal, events.index("forward-stopped"))
                self.assertLess(events.index("forward-stopped"), events.index("stop:ui,kong-third-party"))
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
