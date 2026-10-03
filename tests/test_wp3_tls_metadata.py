#!/usr/bin/env python3
"""Pure tests for API-listener TLS policy extraction from nginx -T."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tests/harness/wp3_tls_metadata.py"
SPEC = importlib.util.spec_from_file_location("wp3_tls_metadata", MODULE_PATH)
tls_metadata = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(tls_metadata)

PINNED_IMAGE = {
    "digest": tls_metadata.PINNED_GATEWAY_IMAGE_DIGEST,
    "architecture": "arm64",
}
ADMIN_TLS = {
    "metadata_source": "admin_root_configuration",
    "cipher_suite": "modern",
    "protocols": [],
}

DEFAULT_MAIN = (
    "include 'nginx-inject.conf';\n"
    "events { worker_connections 1024; }\n"
    "http {\n"
    "  include 'nginx-kong.conf';\n"
    "}\n"
)
DEFAULT_KONG = (
    "include 'nginx-kong-inject.conf';\n"
    "server {\n"
    "  listen 0.0.0.0:8443 ssl;\n"
    "  server_name kong;\n"
    "}\n"
)


def dump_with(
    *,
    main: str = DEFAULT_MAIN,
    main_inject: str = "",
    kong: str = DEFAULT_KONG,
    kong_inject: str = "ssl_protocols TLSv1.3;\n",
    diagnostics_first: bool = False,
) -> bytes:
    sections = {
        "nginx.conf": main,
        "nginx-inject.conf": main_inject,
        "nginx-kong.conf": kong,
        "nginx-kong-inject.conf": kong_inject,
    }
    diagnostics = (
        "nginx: the configuration file /usr/local/kong/nginx.conf syntax is ok\n"
        "nginx: configuration file /usr/local/kong/nginx.conf test is successful\n"
    )
    result = diagnostics if diagnostics_first else ""
    for name in tls_metadata.EXPECTED_FILES:
        result += f"# configuration file /usr/local/kong/{name}:\n{sections[name]}"
    if not diagnostics_first:
        result += diagnostics
    return result.encode("utf-8")


def assess(
    config: bytes,
    *,
    dump_succeeded=True,
    version=tls_metadata.PINNED_OPENRESTY_VERSION,
    image=None,
    admin=None,
):
    return tls_metadata.derive_effective_inbound_tls_policy(
        config,
        dump_succeeded=dump_succeeded,
        openresty_version=version,
        image_metadata=PINNED_IMAGE if image is None else image,
        admin_tls_metadata=ADMIN_TLS if admin is None else admin,
    )


class WP3TlsMetadataTests(unittest.TestCase):
    def test_http_parent_and_target_server_apply_to_exact_api_listener(self):
        kong = (
            "include 'nginx-kong-inject.conf';\n"
            "server { listen 0.0.0.0:8443 ssl; ssl_protocols TLSv1.3; }\n"
            "server { listen 127.0.0.1:8001; ssl_protocols TLSv1.2; }\n"
        )
        result = assess(dump_with(kong=kong, kong_inject="ssl_protocols TLSv1.3;\n"))
        self.assertEqual(result["metadata_source"], "validated_nginx_t_dump")
        self.assertEqual(result["image_binding"], "pinned_gateway_image")
        self.assertEqual(result["openresty_version"], "pinned_openresty_1_29_2_5")
        self.assertEqual(result["cipher_suite"], "modern")
        self.assertEqual(result["protocols"], ["TLSv1.3"])
        # Only the HTTP parent and exact API server apply; the unrelated Admin
        # server's TLSv1.2 directive is excluded from the effective count.
        self.assertEqual(result["active_ssl_protocol_directive_count"], 2)
        self.assertEqual(result["admin_requested_protocols_status"], "not_proven")
        self.assertEqual(result["admin_requested_protocols"], [])
        self.assertIs(result["admin_protocols_are_effective"], False)
        self.assertIs(result["effective_inbound_tls_proven"], True)

    def test_api_server_directive_can_supply_policy_without_parent_setting(self):
        kong = (
            "include 'nginx-kong-inject.conf';\n"
            "server { listen 0.0.0.0:8443 ssl; ssl_protocols TLSv1.3; }\n"
        )
        result = assess(dump_with(kong=kong, kong_inject=""))
        self.assertIs(result["effective_inbound_tls_proven"], True)
        self.assertEqual(result["active_ssl_protocol_directive_count"], 1)

    def test_http_include_injection_is_parsed_at_inherited_http_scope(self):
        result = assess(dump_with(kong_inject="ssl_protocols TLSv1.3;\n"))
        self.assertIs(result["effective_inbound_tls_proven"], True)
        self.assertEqual(result["active_ssl_protocol_directive_count"], 1)

    def test_admin_requested_protocols_are_separate_from_effective_policy(self):
        admin = {**ADMIN_TLS, "protocols": ["TLSv1.2", "TLSv1.3"]}
        result = assess(dump_with(), admin=admin)
        self.assertEqual(result["admin_requested_protocols_status"], "reported")
        self.assertEqual(result["admin_requested_protocols"], ["TLSv1.2", "TLSv1.3"])
        self.assertEqual(result["protocols"], ["TLSv1.3"])
        self.assertIs(result["admin_protocols_are_effective"], False)
        self.assertIs(result["effective_inbound_tls_proven"], True)

    def test_stream_only_policy_cannot_prove_http_api_listener(self):
        main = (
            "include 'nginx-inject.conf';\n"
            "events {}\n"
            "http { include 'nginx-kong.conf'; }\n"
            "stream { ssl_protocols TLSv1.3; server { listen 0.0.0.0:8443; } }\n"
        )
        result = assess(dump_with(main=main, kong_inject=""))
        self.assertIs(result["effective_inbound_tls_proven"], False)
        self.assertEqual(result["protocols"], [])
        self.assertEqual(result["active_ssl_protocol_directive_count"], 0)

    def test_unrelated_http_server_policy_cannot_prove_api_server(self):
        kong = (
            "include 'nginx-kong-inject.conf';\n"
            "server { listen 0.0.0.0:8443 ssl; }\n"
            "server { listen 127.0.0.1:8001 ssl; ssl_protocols TLSv1.3; }\n"
        )
        result = assess(dump_with(kong=kong, kong_inject=""))
        self.assertIs(result["effective_inbound_tls_proven"], False)
        self.assertEqual(result["active_ssl_protocol_directive_count"], 0)

    def test_http_inheritance_and_target_override_must_both_be_tls13(self):
        kong = (
            "include 'nginx-kong-inject.conf';\n"
            "server { listen 0.0.0.0:8443 ssl; ssl_protocols TLSv1.2; }\n"
        )
        result = assess(dump_with(kong=kong, kong_inject="ssl_protocols TLSv1.3;\n"))
        self.assertIs(result["effective_inbound_tls_proven"], False)
        self.assertEqual(result["protocols"], [])
        self.assertEqual(result["active_ssl_protocol_directive_count"], 2)

    def test_tls12_weak_duplicate_unknown_and_malformed_target_values_fail(self):
        for value in (
            "ssl_protocols TLSv1.2;",
            "ssl_protocols TLSv1.2 TLSv1.3;",
            "ssl_protocols TLSv1.3 TLSv1.3;",
            "ssl_protocols UNKNOWN;",
            "ssl_protocols TLSv1.3",
        ):
            with self.subTest(value=value):
                kong = (
                    "include 'nginx-kong-inject.conf';\n"
                    f"server {{ listen 0.0.0.0:8443 ssl; {value} }}\n"
                )
                result = assess(dump_with(kong=kong, kong_inject=""))
                self.assertIs(result["effective_inbound_tls_proven"], False)
                self.assertEqual(result["protocols"], [])

    def test_conflicting_http_parent_directive_fails_even_with_tls13_override(self):
        kong = (
            "include 'nginx-kong-inject.conf';\n"
            "server { listen 0.0.0.0:8443 ssl; ssl_protocols TLSv1.3; }\n"
        )
        result = assess(dump_with(kong=kong, kong_inject="ssl_protocols TLSv1.2;\n"))
        self.assertIs(result["effective_inbound_tls_proven"], False)
        self.assertEqual(result["protocols"], [])

    def test_http_or_target_ssl_conf_command_prevents_effective_policy_proof(self):
        api_server = (
            "include 'nginx-kong-inject.conf';\n"
            "server { listen 0.0.0.0:8443 ssl; }\n"
        )
        for scope_config in (
            (
                "ssl_conf_command Protocol TLSv1.3;\n",
                api_server,
            ),
            (
                "",
                api_server.replace(
                    "listen 0.0.0.0:8443 ssl;",
                    "listen 0.0.0.0:8443 ssl; ssl_conf_command Protocol TLSv1.3;",
                ),
            ),
            (
                "",
                api_server.replace(
                    "listen 0.0.0.0:8443 ssl;",
                    "listen 0.0.0.0:8443 ssl; ssl_conf_command MinProtocol TLSv1.2;",
                ),
            ),
        ):
            with self.subTest(http_inject=scope_config[0], api=scope_config[1]):
                result = assess(dump_with(
                    kong=scope_config[1],
                    kong_inject=scope_config[0] + "ssl_protocols TLSv1.3;\n",
                ))
                self.assertIs(result["effective_inbound_tls_proven"], False)
                self.assertEqual(result["protocols"], [])

    def test_stream_and_proxy_ssl_conf_commands_do_not_override_api_listener(self):
        main = (
            "include 'nginx-inject.conf';\n"
            "events {}\n"
            "http { include 'nginx-kong.conf'; }\n"
            "stream { ssl_conf_command Protocol TLSv1.2; }\n"
        )
        kong = (
            "include 'nginx-kong-inject.conf';\n"
            "server {\n"
            "  listen 0.0.0.0:8443 ssl;\n"
            "  proxy_ssl_conf_command Protocol TLSv1.2;\n"
            "}\n"
        )
        result = assess(dump_with(main=main, kong=kong))
        self.assertIs(result["effective_inbound_tls_proven"], True)

    def test_comment_and_lua_decoys_do_not_change_http_scope(self):
        kong = (
            "include 'nginx-kong-inject.conf';\n"
            "init_by_lua_block {\n"
            "  local x = 'ssl_protocols TLSv1.2; { }';\n"
            "  -- ssl_protocols TLSv1.2; }\n"
            "}\n"
            "server { listen 0.0.0.0:8443 ssl; }\n"
        )
        result = assess(dump_with(kong=kong, kong_inject=(
            "# ssl_protocols TLSv1.2;\n"
            "ssl_protocols TLSv1.3; # trailing decoy ssl_protocols TLSv1.2;\n"
        )))
        self.assertIs(result["effective_inbound_tls_proven"], True)
        self.assertEqual(result["active_ssl_protocol_directive_count"], 1)

    def test_quoted_and_lua_only_protocol_tokens_do_not_prove_policy(self):
        kong = (
            "include 'nginx-kong-inject.conf';\n"
            "server { listen 0.0.0.0:8443 ssl; }\n"
            "init_by_lua_block { local x = 'ssl_protocols TLSv1.3;'; }\n"
        )
        result = assess(dump_with(kong=kong, kong_inject=""))
        self.assertIs(result["effective_inbound_tls_proven"], False)
        self.assertEqual(result["active_ssl_protocol_directive_count"], 0)

    def test_wrong_or_ambiguous_api_listener_fails_closed(self):
        for listen in (
            "listen 127.0.0.1:8443 ssl;",
            "listen 0.0.0.0:8444 ssl;",
            "listen 0.0.0.0:8443;",
            "listen 8443 ssl;",
            "listen [::]:8443 ssl;",
        ):
            with self.subTest(listen=listen):
                kong = (
                    "include 'nginx-kong-inject.conf';\n"
                    f"server {{ {listen} }}\n"
                )
                result = assess(dump_with(kong=kong))
                self.assertIs(result["effective_inbound_tls_proven"], False)

        conflicting = (
            "include 'nginx-kong-inject.conf';\n"
            "server { listen 0.0.0.0:8443 ssl; }\n"
            "server { listen 8443 ssl; }\n"
        )
        self.assertIs(assess(dump_with(kong=conflicting))["effective_inbound_tls_proven"], False)

    def test_include_graph_and_file_markers_must_match_pinned_template(self):
        bad_graphs = (
            dump_with(main=DEFAULT_MAIN.replace("nginx-kong.conf", "other.conf")),
            dump_with(kong=DEFAULT_KONG.replace("nginx-kong-inject.conf", "other.conf")),
            dump_with(main=DEFAULT_MAIN.replace("include 'nginx-inject.conf';", "")),
            dump_with(main_inject="include 'unknown.conf';\n"),
        )
        for config in bad_graphs:
            with self.subTest(length=len(config)):
                self.assertIs(assess(config)["effective_inbound_tls_proven"], False)

        duplicate_marker = dump_with() + b"# configuration file /usr/local/kong/nginx-kong.conf:\n"
        self.assertIs(assess(duplicate_marker)["effective_inbound_tls_proven"], False)

    def test_inline_contexts_are_scoped_and_malformed_nesting_is_rejected(self):
        inline = (
            "include 'nginx-inject.conf'; events {} "
            "http { include 'nginx-kong.conf'; }\n"
        )
        result = assess(dump_with(main=inline))
        self.assertIs(result["effective_inbound_tls_proven"], True)

        malformed = dump_with(kong="include 'nginx-kong-inject.conf';\nserver {")
        self.assertIs(assess(malformed)["effective_inbound_tls_proven"], False)
        quoted = dump_with(kong=(
            "include 'nginx-kong-inject.conf';\n"
            "server { listen 0.0.0.0:8443 ssl; }\n"
            'log_format main \'{"x":"brace } ssl_protocols TLSv1.3;"}\';\n'
        ))
        self.assertIs(assess(quoted)["effective_inbound_tls_proven"], True)

    def test_dump_envelope_boundaries_and_environment_binding_fail_closed(self):
        valid = dump_with()
        cases = (
            (valid + b" " * (tls_metadata.MAX_NGINX_CONFIG_BYTES + 1), {}),
            (b"\xff", {}),
            (valid, {"dump_succeeded": 1}),
            (valid, {"dump_succeeded": False}),
            (valid, {"version": "openresty/1.29.2.4"}),
            (valid, {"version": b"openresty/1.29.2.5"}),
            (valid, {"image": {"digest": "0" * 64, "architecture": "arm64"}}),
            (valid, {"image": {"digest": tls_metadata.PINNED_GATEWAY_IMAGE_DIGEST, "architecture": "amd64"}}),
            (valid, {"image": {**PINNED_IMAGE, "extra": "value"}}),
            (valid, {"admin": {**ADMIN_TLS, "cipher_suite": "legacy"}}),
            (valid, {"admin": {**ADMIN_TLS, "metadata_source": "untrusted"}}),
            (valid, {"admin": {**ADMIN_TLS, "extra": "untrusted"}}),
        )
        for config, overrides in cases:
            with self.subTest(overrides=overrides, oversized=len(config) > tls_metadata.MAX_NGINX_CONFIG_BYTES):
                self.assertIs(assess(config, **overrides)["effective_inbound_tls_proven"], False)

        bad_marker = valid.replace(b"test is successful", b"test failed")
        self.assertIs(assess(bad_marker)["effective_inbound_tls_proven"], False)

        # The runtime combines nginx -T stdout followed by stderr, placing the
        # two exact success diagnostics after the final file section.
        suffix_diagnostics = dump_with()
        self.assertIs(assess(suffix_diagnostics)["effective_inbound_tls_proven"], True)
        prefix_diagnostics = dump_with(diagnostics_first=True)
        self.assertIs(assess(prefix_diagnostics)["effective_inbound_tls_proven"], True)
        self.assertIs(
            assess(b"unexpected diagnostic\n" + suffix_diagnostics)["effective_inbound_tls_proven"],
            False,
        )
        self.assertIs(
            assess(suffix_diagnostics + b"nginx: unexpected warning\n")["effective_inbound_tls_proven"],
            False,
        )

    def test_unknown_admin_values_and_raw_configuration_are_never_echoed(self):
        sentinel = "WP3-PRIVATE-METADATA-SENTINEL"
        admin = {**ADMIN_TLS, "protocols": [sentinel]}
        result = assess(dump_with(), admin=admin)
        self.assertEqual(result["admin_requested_protocols_status"], "not_proven")
        self.assertEqual(result["admin_requested_protocols"], [])
        self.assertNotIn(sentinel, repr(result))

        config_sentinel = "WP3-RAW-CONFIG-SECRET-SENTINEL"
        config = dump_with(kong_inject=f"# {config_sentinel}\nssl_protocols TLSv1.3;\n")
        result = assess(config)
        self.assertNotIn(config_sentinel, repr(result))
        self.assertNotIn("/usr/local/kong", repr(result))
        self.assertEqual(set(result), {
            "metadata_source", "image_binding", "openresty_version", "cipher_suite",
            "protocols", "active_ssl_protocol_directive_count",
            "admin_requested_protocols_status", "admin_requested_protocols",
            "admin_protocols_are_effective", "effective_inbound_tls_proven",
        })


if __name__ == "__main__":
    unittest.main(verbosity=2)
