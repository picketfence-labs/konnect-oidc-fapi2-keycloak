"""Fail-closed parsing of the pinned WP3 NGINX inbound TLS configuration dump.

This module accepts only bounded in-memory evidence from the isolated, pinned
gateway. It never emits configuration text, paths, diagnostics, or arbitrary
input values in its result. The parser understands only the pinned image's
four-file include graph and the API listener configured by the WP3 fixture.
"""

from __future__ import annotations

import re


MAX_NGINX_CONFIG_BYTES = 1_048_576
MAX_NGINX_TOKENS = 250_000
MAX_NGINX_BLOCK_DEPTH = 64
PINNED_OPENRESTY_VERSION = "openresty/1.29.2.5"
PINNED_GATEWAY_IMAGE_DIGEST = "e2678b4cb534fc9d6a17288d83457d6cbea235a6331dc4982e021300ccb668c4"
PINNED_GATEWAY_IMAGE_ARCHITECTURE = "arm64"
EXPECTED_NGINX_CONFIG_PATH = "/usr/local/kong/nginx.conf"
EXPECTED_FILES = (
    "nginx.conf",
    "nginx-inject.conf",
    "nginx-kong.conf",
    "nginx-kong-inject.conf",
)
ALLOWED_PROTOCOLS = ("TLSv1.2", "TLSv1.3")
TARGET_API_LISTEN = ("listen", "0.0.0.0:8443", "ssl")

_SYNTAX_OK = f"nginx: the configuration file {EXPECTED_NGINX_CONFIG_PATH} syntax is ok"
_TEST_OK = f"nginx: configuration file {EXPECTED_NGINX_CONFIG_PATH} test is successful"
_MAIN_CONFIG_MARKER = f"# configuration file {EXPECTED_NGINX_CONFIG_PATH}:"
_MARKER_PREFIX = "# configuration file "
_ALLOWED_MARKERS = {
    f"# configuration file /usr/local/kong/{name}:": name for name in EXPECTED_FILES
}


def _admin_protocol_evidence(admin_tls_metadata: object) -> tuple[str, list[str], bool]:
    """Return a safe copy of Admin-requested protocols, never effective policy."""
    if (
        type(admin_tls_metadata) is not dict
        or set(admin_tls_metadata) != {"metadata_source", "cipher_suite", "protocols"}
        or admin_tls_metadata.get("metadata_source") != "admin_root_configuration"
    ):
        return "not_proven", [], False

    protocols = admin_tls_metadata.get("protocols")
    if (
        type(protocols) is list
        and protocols
        and all(type(item) is str and item in ALLOWED_PROTOCOLS for item in protocols)
        and len(set(protocols)) == len(protocols)
    ):
        return "reported", list(protocols), admin_tls_metadata.get("cipher_suite") == "modern"
    # An empty or unrecognized Admin field remains unknown. It is not used to
    # infer effective policy, which must be inherited by the API HTTP listener.
    return "not_proven", [], admin_tls_metadata.get("cipher_suite") == "modern"


def _lex_nginx(text: str) -> list[tuple[str, str]] | None:
    """Tokenize the small NGINX subset needed for scope and include validation.

    Quoted strings and comments are opaque, so braces and directive-looking
    text inside them cannot establish policy. Lua line comments are skipped;
    unsupported or unbalanced syntax fails closed later.
    """
    tokens: list[tuple[str, str]] = []
    index = 0
    length = len(text)
    while index < length:
        character = text[index]
        if character.isspace():
            index += 1
            continue
        if character == "#" or text.startswith("--", index):
            newline = text.find("\n", index)
            index = length if newline < 0 else newline + 1
            continue
        if character in "{};":
            tokens.append(("punct", character))
            index += 1
        elif character in "\"'":
            quote = character
            index += 1
            value: list[str] = []
            escaped = False
            while index < length:
                current = text[index]
                index += 1
                if escaped:
                    value.append(current)
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    break
                else:
                    value.append(current)
            else:
                return None
            if escaped:
                return None
            tokens.append(("string", "".join(value)))
        else:
            start = index
            while index < length and not text[index].isspace() and text[index] not in "{};#\"'":
                if text.startswith("--", index):
                    break
                index += 1
            if start == index:
                # A standalone unsupported token is ambiguous for the narrow
                # pinned-template parser; it must not be silently discarded.
                return None
            tokens.append(("word", text[start:index]))
        if len(tokens) > MAX_NGINX_TOKENS:
            return None
    return tokens


def _command_name(statement: list[tuple[str, str]]) -> str | None:
    if not statement or statement[0][0] != "word":
        return None
    return statement[0][1].lower()


def _lua_block(command: str | None) -> bool:
    return command is not None and (
        command.endswith("_by_lua_block")
        or command in {"lua_block", "set_by_lua_block"}
    )


def _skip_block(tokens: list[tuple[str, str]], open_index: int) -> int | None:
    """Return after a balanced code block; strings are already opaque tokens."""
    depth = 1
    index = open_index + 1
    while index < len(tokens):
        kind, value = tokens[index]
        if kind == "punct" and value == "{":
            depth += 1
            if depth > MAX_NGINX_BLOCK_DEPTH:
                return None
        elif kind == "punct" and value == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return None


def _parse_section(text: str, initial_scope: str) -> dict | None:
    tokens = _lex_nginx(text)
    if tokens is None:
        return None

    result = {
        "http_blocks": 0,
        "includes": [],
        "http_protocols": [],
        "http_ssl_conf_commands": 0,
        "http_servers": [],
        "stream_protocols": [],
        "other_ssl_protocols": 0,
        "invalid_scope": False,
        "block_count": 0,
    }
    cursor = 0

    def parse_scope(scope: str, server: dict | None, depth: int, nested: bool) -> bool:
        nonlocal cursor
        if depth > MAX_NGINX_BLOCK_DEPTH:
            return False
        statement: list[tuple[str, str]] = []
        while cursor < len(tokens):
            kind, value = tokens[cursor]
            cursor += 1
            if kind != "punct":
                statement.append((kind, value))
                continue

            if value == ";":
                command = _command_name(statement)
                if command == "ssl_protocols":
                    setting_valid = (
                        len(statement) == 2
                        and statement[1] == ("word", "TLSv1.3")
                    )
                    if scope == "http":
                        result["http_protocols"].append(setting_valid)
                    elif scope == "server" and server is not None:
                        server["protocols"].append(setting_valid)
                    elif scope in {"stream", "stream_server"}:
                        result["stream_protocols"].append(setting_valid)
                    else:
                        result["other_ssl_protocols"] += 1
                        result["invalid_scope"] = True
                elif command == "ssl_conf_command":
                    if scope == "http":
                        result["http_ssl_conf_commands"] += 1
                    elif scope == "server" and server is not None:
                        server["ssl_conf_commands"] += 1
                elif command == "include":
                    if len(statement) != 2 or statement[1][0] not in {"word", "string"}:
                        result["invalid_scope"] = True
                    else:
                        result["includes"].append((scope, statement[1][1]))
                elif command == "listen" and scope == "server" and server is not None:
                    server["listen_statements"].append(tuple(statement))
                statement = []
                continue

            if value == "}":
                if statement:
                    return False
                return nested

            # Opening a block. The complete header must be unambiguous.
            command = _command_name(statement)
            if command is None:
                return False
            result["block_count"] += 1
            if result["block_count"] > MAX_NGINX_TOKENS:
                return False

            if _lua_block(command):
                statement = []
                after = _skip_block(tokens, cursor - 1)
                if after is None:
                    return False
                cursor = after
                continue

            if scope == "main" and command == "http" and len(statement) == 1:
                child_scope = "http"
                result["http_blocks"] += 1
                child_server = None
            elif scope == "main" and command == "stream":
                child_scope = "stream"
                child_server = None
            elif scope == "http" and command == "server":
                child_scope = "server"
                child_server = {
                    "protocols": [],
                    "ssl_conf_commands": 0,
                    "listen_statements": [],
                }
                result["http_servers"].append(child_server)
            elif scope == "stream" and command == "server":
                child_scope = "stream_server"
                child_server = None
            elif scope == "main" and command == "events":
                child_scope = "other"
                child_server = None
            elif command in {"http", "stream", "server"}:
                # These context declarations outside the pinned ancestry make
                # include inheritance ambiguous or invalid.
                result["invalid_scope"] = True
                child_scope = "other"
                child_server = None
            else:
                child_scope = "other"
                child_server = None

            statement = []
            if not parse_scope(child_scope, child_server, depth + 1, True):
                return False
        return not nested and not statement

    if not parse_scope(initial_scope, None, 0, False):
        return None
    if cursor != len(tokens):
        return None
    return result


def _split_config_dump(config_dump: bytes) -> dict[str, str] | None:
    if type(config_dump) is not bytes or not config_dump or len(config_dump) > MAX_NGINX_CONFIG_BYTES:
        return None
    try:
        text = config_dump.decode("utf-8", errors="strict")
    except UnicodeError:
        return None
    if "\x00" in text:
        return None

    lines = text.splitlines()
    if lines.count(_SYNTAX_OK) != 1 or lines.count(_TEST_OK) != 1:
        return None

    sections: dict[str, list[str]] = {}
    active_name: str | None = None
    for line in lines:
        if line in {_SYNTAX_OK, _TEST_OK}:
            # nginx -T writes these on stderr. WP3 combines stdout+stderr, so
            # they may follow every config file rather than precede the dump.
            continue
        if line.startswith(_MARKER_PREFIX):
            name = _ALLOWED_MARKERS.get(line)
            if name is None or name in sections:
                return None
            sections[name] = []
            active_name = name
            continue
        if active_name is None:
            # Unknown preamble/diagnostic text is not part of the pinned
            # nginx -T envelope and must not be silently ignored.
            return None
        sections[active_name].append(line)

    if set(sections) != set(EXPECTED_FILES) or _MAIN_CONFIG_MARKER not in lines:
        return None
    return {name: "\n".join(body) for name, body in sections.items()}


def _valid_include_graph(parsed: dict[str, dict]) -> bool:
    main = parsed["nginx.conf"]
    injected_main = parsed["nginx-inject.conf"]
    kong = parsed["nginx-kong.conf"]
    injected_http = parsed["nginx-kong-inject.conf"]

    if any(section["invalid_scope"] for section in parsed.values()):
        return False
    if main["http_blocks"] != 1:
        return False
    if injected_main["block_count"] != 0 or injected_main["includes"]:
        return False
    if injected_http["includes"]:
        return False

    if sorted(main["includes"]) != sorted([
        ("main", "nginx-inject.conf"),
        ("http", "nginx-kong.conf"),
    ]):
        return False
    if kong["includes"] != [("http", "nginx-kong-inject.conf")]:
        return False
    return True


def _parse_config_dump(config_dump: bytes) -> tuple[bool, int]:
    """Prove TLSv1.3 applies to the exact API HTTP TLS listener."""
    sections = _split_config_dump(config_dump)
    if sections is None:
        return False, 0

    parsed: dict[str, dict] = {}
    for name, body in sections.items():
        initial_scope = "main" if name in {"nginx.conf", "nginx-inject.conf"} else "http"
        section = _parse_section(body, initial_scope)
        if section is None:
            return False, 0
        parsed[name] = section

    if not _valid_include_graph(parsed):
        return False, 0

    http_protocols = []
    http_ssl_conf_commands = 0
    servers: list[dict] = []
    stream_protocols = []
    for section in parsed.values():
        http_protocols.extend(section["http_protocols"])
        http_ssl_conf_commands += section["http_ssl_conf_commands"]
        servers.extend(section["http_servers"])
        stream_protocols.extend(section["stream_protocols"])

    # Stream TLS never configures an HTTP listener. Retain it only as parsed
    # structure; it cannot contribute to the effective count or proof.
    del stream_protocols

    target_servers: list[dict] = []
    ambiguous_tls_port = False
    for server in servers:
        target_listens = 0
        for statement in server["listen_statements"]:
            values = tuple(value for kind, value in statement)
            if values == TARGET_API_LISTEN:
                target_listens += 1
            elif any("8443" in value for value in values[1:]) and "ssl" in values[1:]:
                ambiguous_tls_port = True
        if target_listens:
            if target_listens != 1:
                ambiguous_tls_port = True
            target_servers.append(server)

    if ambiguous_tls_port or len(target_servers) != 1:
        return False, 0

    target_protocols = target_servers[0]["protocols"]
    applicable_protocols = http_protocols + target_protocols
    directive_count = len(applicable_protocols)
    applicable_ssl_conf_commands = (
        http_ssl_conf_commands + target_servers[0]["ssl_conf_commands"]
    )
    proven = (
        directive_count >= 1
        and applicable_ssl_conf_commands == 0
        and all(applicable_protocols)
        and parsed["nginx.conf"]["http_blocks"] == 1
    )
    return proven, directive_count


def derive_effective_inbound_tls_policy(
    config_dump: object,
    *,
    dump_succeeded: object,
    openresty_version: object,
    image_metadata: object,
    admin_tls_metadata: object,
) -> dict:
    """Return sanitized TLS evidence bound to the WP3 API HTTP listener.

    ``image_metadata`` is the already-validated ``kong-api`` row returned by
    ``prepare_wp3_preview.inspect_images``. Admin's requested protocol field is
    retained separately; it never supplies the effective listener setting.
    """
    image_bound = (
        type(image_metadata) is dict
        and set(image_metadata) == {"digest", "architecture"}
        and image_metadata.get("digest") == PINNED_GATEWAY_IMAGE_DIGEST
        and image_metadata.get("architecture") == PINNED_GATEWAY_IMAGE_ARCHITECTURE
    )
    version_bound = type(openresty_version) is str and openresty_version == PINNED_OPENRESTY_VERSION
    admin_protocol_status, admin_requested_protocols, admin_modern_cipher = _admin_protocol_evidence(
        admin_tls_metadata,
    )
    admin_cipher_suite = (
        "modern"
        if type(admin_tls_metadata) is dict
        and set(admin_tls_metadata) == {"metadata_source", "cipher_suite", "protocols"}
        and admin_tls_metadata.get("metadata_source") == "admin_root_configuration"
        and admin_tls_metadata.get("cipher_suite") == "modern"
        else "not_proven"
    )

    source = "not_proven"
    effective_protocols: list[str] = []
    active_directive_count = 0
    if dump_succeeded is True and version_bound and image_bound:
        parsed, active_directive_count = _parse_config_dump(config_dump)
        if parsed:
            source = "validated_nginx_t_dump"
            effective_protocols = ["TLSv1.3"]

    policy_proven = (
        source == "validated_nginx_t_dump"
        and image_bound
        and version_bound
        and admin_modern_cipher
        and admin_cipher_suite == "modern"
        and effective_protocols == ["TLSv1.3"]
        and active_directive_count >= 1
    )
    return {
        "metadata_source": source,
        "image_binding": "pinned_gateway_image" if image_bound else "not_proven",
        "openresty_version": "pinned_openresty_1_29_2_5" if version_bound else "not_proven",
        "cipher_suite": admin_cipher_suite,
        "protocols": effective_protocols,
        "active_ssl_protocol_directive_count": active_directive_count,
        "admin_requested_protocols_status": admin_protocol_status,
        "admin_requested_protocols": admin_requested_protocols,
        "admin_protocols_are_effective": False,
        "effective_inbound_tls_proven": policy_proven,
    }
