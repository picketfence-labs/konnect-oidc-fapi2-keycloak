#!/usr/bin/env python3
"""Run one fixed WP5 build phase and emit only bounded, sanitized diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable


PINNED_COMMIT = "aa9fe3fba0c6cd5770f19a49378c55f4378cf544"
HANDLER_RELATIVE = pathlib.Path(
    "quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/integration/resteasy/"
    "TransactionalSessionHandler.java"
)
OBSERVER_RELATIVE = HANDLER_RELATIVE.parent / "AsPeerObserver.java"
HANDLER_AFTER_SHA256 = "0bfae99bf4ad1e3c69eb3c687deb9f5e0cddf44324613cac7df35b752a6af6e2"
OBSERVER_SHA256 = "435e50c8dd67d31334263369924e17b9c99c295b066f7ba444209e3ac130992f"
PATCHED_PATHS = {str(HANDLER_RELATIVE), str(OBSERVER_RELATIVE)}

V4_SOURCE = pathlib.Path("/private/tmp/wp5-as-observer-build-20261004-v4/source")
V4_OUTPUT = pathlib.Path("/private/tmp/wp5-as-observer-build-20261004-v4/output")
V4_WORKSPACE = pathlib.Path("/private/tmp/wp5-as-observer-build-20261004-v4")
V4_CONTAINER = "wp5-as-observer-builder-20261004-v4"
V4_IMAGE = "wp5-as-observer-builder:20261004-5a-v4"
V4_CACHE = "wp5-as-observer-m2-cache-20261004-v4"
BASE_IMAGE = (
    "eclipse-temurin:21-jdk@sha256:681c5a2969ee6bcd535dac7d582ddbbc1ea81ee5d6187a426458ca796b345687"
)
BASE_ID = "sha256:05e5dc64672d5a2233e7a3c7b527b43d6e7d0bb8231d21582c1729282404d259"
BUILDER_CONTEXT = pathlib.Path(__file__).resolve().parent / "builder"

OWNER_LABEL = "org.picketfence.wp5.owner"
PHASE_LABEL = "org.picketfence.wp5.phase"
OWNER = "wp5-luna"
PHASE_LABEL_VALUE = "observer-build-only"

MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_DIAGNOSTIC_LOCATIONS = 32
MAX_DIAGNOSTIC_COUNT = 10000
PHASE_DEADLINES = {
    "derived_builder_build": 1200,
    "runtime_module_compile": 22 * 60,
    "server_distribution_build": 47 * 60,
}
CONTAINER_TIMEOUTS = {
    "runtime_module_compile": "20m",
    "server_distribution_build": "45m",
}
ALLOWED_RESULT = {"success", "nonzero_exit", "timeout", "output_limit", "runner_failure"}
ALLOWED_ERROR = {
    "compiler_failure",
    "dependency_resolution",
    "dns_resolution",
    "tls_certificate_validation",
    "http_401",
    "http_403",
    "http_404",
    "http_429",
    "http_5xx",
    "disk_space",
    "memory_limit",
    "package_inventory_ordering",
    "maven_goal_failure",
    "docker_build_failure",
    "docker_execution_failure",
    "process_termination_unverified",
    "timeout",
    "nonzero_unclassified",
}
ALLOWED_GOAL = {"compiler", "dependency", "quarkus", "enforcer", "resources", "other_known"}
ALLOWED_COMPILER_DIAGNOSTIC = {
    "cannot_find_symbol",
    "package_not_found",
    "incompatible_types",
    "method_resolution",
    "override_mismatch",
    "inaccessible_type",
    "ambiguous_reference",
    "invalid_reference",
}

GOAL_MAP = {
    "maven-compiler-plugin": "compiler",
    "maven-dependency-plugin": "dependency",
    "quarkus-maven-plugin": "quarkus",
    "maven-enforcer-plugin": "enforcer",
    "maven-resources-plugin": "resources",
    "maven-surefire-plugin": "other_known",
    "maven-install-plugin": "other_known",
    "maven-clean-plugin": "other_known",
}
PROJECT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,160}$")
POM_GOAL_RE = re.compile(
    r"Failed to execute goal ([A-Za-z0-9_.:-]{1,240})(?: \([^\r\n)]{1,120}\))? on project ([A-Za-z0-9_.-]{1,160})"
)
MAVEN_PLUGIN_START_RE = re.compile(
    r"^\[INFO\]\s+---\s+([^\s:]{1,120}):[^\s:]{1,80}:([^\s(]{1,80})"
    r"(?:\s+\([^\r\n)]{1,120}\))?\s+@\s+([A-Za-z0-9_.-]{1,160})\s+---\s*$"
)
REACTOR_FAILURE_RE = re.compile(
    r"^\[(?:INFO|ERROR)\]\s+(.+?)\s+\.{2,}\s+FAILURE"
    r"(?:\s+\[\s*(?:[0-9]{1,8}(?:\.[0-9]{1,3})?\s*(?:ms|s)"
    r"|[0-9]{1,4}:[0-5][0-9](?::[0-5][0-9])?(?:\.[0-9]{1,3})?\s*(?:min|h))\s*\])?\s*$"
)
MAVEN_3_PLUGIN_SHORT_NAMES = {
    "compiler": "compiler",
    "dependency": "dependency",
    "quarkus": "quarkus",
    "enforcer": "enforcer",
    "resources": "resources",
    "surefire": "other_known",
    "install": "other_known",
    "clean": "other_known",
}
COMPILER_DIAGNOSTIC_RE = re.compile(
    r"^(?:\[ERROR\]\s*)?(?P<path>(?:/workspace/source/)?[A-Za-z0-9_./-]{1,512}\.java)"
    r"(?::\[(?P<maven_line>[0-9]{1,8}),[0-9]{1,8}\]"
    r"|:(?P<javac_line>[0-9]{1,8}):)\s*(?P<message>.*)$",
    re.IGNORECASE,
)
EXPLICIT_COMPILER_FAILURE_RE = re.compile(
    r"\bcompilation (?:error|failure)\b|\bjavac\b.*\b(?:error|failure)\b",
    re.IGNORECASE,
)
COMPILER_ERROR_MARKER_RE = re.compile(
    r"(?:\.java(?::\[[0-9]{1,8},[0-9]{1,8}\]|:[0-9]{1,8}:).*\berror:\s*"
    r"|\bjavac\b.*\berror:\s*|\bcompilation (?:error|failure)\b)",
    re.IGNORECASE,
)
HTTP_RE = re.compile(r"(?:HTTP[/ ]\d(?:\.\d)?\s+|status(?:\s+code)?[=: ]+)(401|403|404|429|5\d\d)\b", re.I)


class CaptureError(Exception):
    """An internal fixed-reason error; never serialize its message."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class StreamDigest:
    name: str
    digest: object = field(default_factory=hashlib.sha256)
    captured_bytes: int = 0
    line_count: int = 0
    pending: bytearray = field(default_factory=bytearray)
    complete: bool = True


@dataclass(frozen=True)
class ModuleIdentity:
    root: str
    project_id: str


@dataclass
class ProjectInventory:
    projects: set[str]
    aliases: dict[str, set[str]]
    modules: list[ModuleIdentity]
    tracked_paths: set[str]

    def canonical_project(self, value: str) -> str | None:
        matches = self.aliases.get(value, set())
        return next(iter(matches)) if len(matches) == 1 else None

    def project_for_source_path(self, relative: str) -> str | None:
        if relative not in self.tracked_paths or not relative.endswith(".java"):
            return None
        if relative.startswith("/") or "\\" in relative or ".." in pathlib.PurePosixPath(relative).parts:
            return None
        matches: list[ModuleIdentity] = []
        for module in self.modules:
            prefix = "" if module.root == "." else module.root.rstrip("/") + "/"
            if relative.startswith(prefix + "src/"):
                matches.append(module)
        if not matches:
            return None
        longest = max(len(module.root) for module in matches)
        owners = {module.project_id for module in matches if len(module.root) == longest}
        return next(iter(owners)) if len(owners) == 1 else None


@dataclass
class Observations:
    errors: set[str] = field(default_factory=set)
    projects: set[str] = field(default_factory=set)
    failed_goal_projects: set[str] = field(default_factory=set)
    goals: set[str] = field(default_factory=set)
    reactor_failures: set[str] = field(default_factory=set)
    plugin_started: set[str] = field(default_factory=set)
    compiler_diagnostic_categories: set[str] = field(default_factory=set)
    diagnostic_locations: dict[tuple[str, int, str], None] = field(default_factory=dict)
    compiler_diagnostic_count: int = 0
    unknown_diagnostic_count: int = 0
    invalid_control_sequence_count: int = 0
    parser_incomplete_line_count: int = 0
    failure_location_identified: bool = False
    diagnostic_locations_truncated: bool = False
    diagnostic_counts_saturated: bool = False
    parser_complete: bool = True


def _safe_host_environment() -> dict[str, str]:
    allowed = (
        "PATH",
        "HOME",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    )
    return {key: os.environ[key] for key in allowed if key in os.environ}


def _project_ids_from_poms(source: pathlib.Path) -> ProjectInventory:
    source = source.resolve(strict=True)
    if source != V4_SOURCE:
        raise CaptureError("source_path_mismatch")
    head = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        capture_output=True,
        timeout=10,
        check=False,
    )
    if head.returncode or head.stdout.decode("ascii", "ignore").strip() != PINNED_COMMIT:
        raise CaptureError("source_commit_mismatch")
    status = subprocess.run(
        ["git", "-C", str(source), "status", "--porcelain", "-z", "--untracked-files=all"],
        capture_output=True,
        timeout=10,
        check=False,
    )
    if status.returncode:
        raise CaptureError("source_status_unavailable")
    records = [item.decode("utf-8", "strict") for item in status.stdout.split(b"\0") if item]
    changed = {record[3:] for record in records if len(record) >= 4}
    if changed != PATCHED_PATHS:
        raise CaptureError("source_patch_inventory_mismatch")
    if hashlib.sha256((source / HANDLER_RELATIVE).read_bytes()).hexdigest() != HANDLER_AFTER_SHA256:
        raise CaptureError("handler_patch_digest_mismatch")
    if hashlib.sha256((source / OBSERVER_RELATIVE).read_bytes()).hexdigest() != OBSERVER_SHA256:
        raise CaptureError("observer_patch_digest_mismatch")

    listing = subprocess.run(
        ["git", "-C", str(source), "ls-files", "-z"],
        capture_output=True,
        timeout=15,
        check=False,
    )
    if listing.returncode:
        raise CaptureError("pom_inventory_unavailable")
    tracked_paths = {
        os.fsdecode(raw)
        for raw in listing.stdout.split(b"\0")
        if raw
    }
    root_pom = source / "pom.xml"
    if "pom.xml" not in tracked_paths or root_pom.is_symlink() or not root_pom.is_file():
        raise CaptureError("root_pom_unavailable")
    pending = [root_pom]
    pom_paths: list[pathlib.Path] = []
    visited: set[pathlib.Path] = set()
    while pending:
        path = pending.pop()
        resolved = path.resolve(strict=True)
        if resolved in visited:
            continue
        if not resolved.is_relative_to(source) or path.is_symlink():
            raise CaptureError("module_path_invalid")
        relative = path.relative_to(source).as_posix()
        if relative not in tracked_paths:
            raise CaptureError("module_pom_untracked")
        visited.add(resolved)
        pom_paths.append(path)
        if len(pom_paths) > 5000:
            raise CaptureError("pom_inventory_out_of_bounds")
        try:
            module_root = ET.parse(path).getroot()
        except (OSError, ET.ParseError):
            raise CaptureError("pom_parse_failed") from None
        module_values: list[str] = []
        for child in list(module_root):
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "modules":
                module_values.extend(
                    (module.text or "").strip()
                    for module in list(child)
                    if module.tag.rsplit("}", 1)[-1] == "module"
                )
            elif tag == "profiles":
                for profile in list(child):
                    if profile.tag.rsplit("}", 1)[-1] != "profile":
                        continue
                    for profile_child in list(profile):
                        if profile_child.tag.rsplit("}", 1)[-1] == "modules":
                            module_values.extend(
                                (module.text or "").strip()
                                for module in list(profile_child)
                                if module.tag.rsplit("}", 1)[-1] == "module"
                            )
        for value in module_values:
            if not value or "${" in value or value.startswith("/") or "\\" in value:
                continue
            candidate = (path.parent / value).resolve(strict=False)
            if not candidate.is_relative_to(source):
                raise CaptureError("module_path_invalid")
            module_pom = candidate / "pom.xml" if candidate.is_dir() or not candidate.suffix else candidate
            if module_pom.name != "pom.xml" or module_pom.is_symlink() or not module_pom.exists():
                raise CaptureError("module_pom_unavailable")
            pending.append(module_pom)
    if not pom_paths:
        raise CaptureError("pom_inventory_empty")
    projects: set[str] = set()
    aliases: dict[str, set[str]] = {}
    module_identities: list[ModuleIdentity] = []
    for path in pom_paths:
        try:
            root = ET.parse(path).getroot()
        except (OSError, ET.ParseError):
            raise CaptureError("pom_parse_failed") from None
        artifact_id = None
        display_name = None
        for child in list(root):
            tag = child.tag.rsplit("}", 1)[-1]
            candidate = (child.text or "").strip()
            if tag == "artifactId" and artifact_id is None:
                artifact_id = candidate
            elif tag == "name" and display_name is None:
                display_name = " ".join(candidate.split())
        if not artifact_id or not PROJECT_RE.fullmatch(artifact_id) or "${" in artifact_id:
            continue
        projects.add(artifact_id)
        aliases.setdefault(artifact_id, set()).add(artifact_id)
        if (
            display_name
            and len(display_name) <= 160
            and "${" not in display_name
            and all(character.isprintable() for character in display_name)
        ):
            aliases.setdefault(display_name, set()).add(artifact_id)
        module_identities.append(ModuleIdentity(path.parent.relative_to(source).as_posix(), artifact_id))
    if not projects:
        raise CaptureError("project_inventory_empty")
    return ProjectInventory(projects, aliases, module_identities, tracked_paths)


def _bounded_increment(observations: Observations, field_name: str) -> None:
    value = getattr(observations, field_name)
    if value >= MAX_DIAGNOSTIC_COUNT:
        observations.diagnostic_counts_saturated = True
        return
    setattr(observations, field_name, value + 1)


def _normalize_terminal_controls(line: bytes) -> bytes | None:
    """Strip bounded SGR/OSC sequences from one complete line; reject other controls."""
    normalized = bytearray()
    index = 0
    while index < len(line):
        current = line[index]
        if current == 0x1B:
            if index + 1 >= len(line):
                return None
            kind = line[index + 1]
            if kind == ord("["):
                end = index + 2
                while end < len(line) and 0x30 <= line[end] <= 0x3F:
                    end += 1
                if end >= len(line) or line[end] != ord("m"):
                    return None
                if any(byte not in b"0123456789;:" for byte in line[index + 2:end]):
                    return None
                index = end + 1
                continue
            if kind == ord("]"):
                end = index + 2
                while end < len(line):
                    if line[end] == 0x07:
                        break
                    if line[end] == 0x1B and end + 1 < len(line) and line[end + 1] == ord("\\"):
                        break
                    end += 1
                if end >= len(line):
                    return None
                index = end + (2 if line[end] == 0x1B else 1)
                continue
            return None
        if current == 0x0D:
            if index == len(line) - 1:
                index += 1
                continue
            return None
        if current < 0x20 and current not in (0x09,):
            return None
        if current == 0x7F:
            return None
        normalized.append(current)
        index += 1
    return bytes(normalized)


def _goal_category(plugin_coordinate: str) -> str | None:
    parts = plugin_coordinate.split(":")
    if len(parts) >= 4:
        plugin_name = parts[1]
    elif len(parts) == 3:
        plugin_name = parts[0]
    else:
        plugin_name = parts[0]
    return GOAL_MAP.get(plugin_name) or MAVEN_3_PLUGIN_SHORT_NAMES.get(plugin_name)


def _compiler_diagnostic_category(message: str) -> str | None:
    lowered = message.lower()
    if "cannot find symbol" in lowered:
        return "cannot_find_symbol"
    if re.search(r"package .+ does not exist", lowered):
        return "package_not_found"
    if "incompatible types" in lowered:
        return "incompatible_types"
    if "no suitable method found" in lowered or "cannot be applied to given types" in lowered:
        return "method_resolution"
    if "does not override or implement a method" in lowered:
        return "override_mismatch"
    if "has private access in" in lowered or "is not public in" in lowered or "cannot access" in lowered:
        return "inaccessible_type"
    if " is ambiguous" in lowered and "reference to " in lowered:
        return "ambiguous_reference"
    if "invalid method reference" in lowered or "unexpected type" in lowered:
        return "invalid_reference"
    return None


def _relative_source_path(path_text: str) -> str | None:
    prefix = "/workspace/source/"
    if path_text.startswith(prefix):
        relative = path_text[len(prefix):]
    elif path_text.startswith("/"):
        return None
    else:
        relative = path_text
    candidate = pathlib.PurePosixPath(relative)
    if (
        not relative
        or "\\" in relative
        or candidate.is_absolute()
        or ".." in candidate.parts
        or len(relative) > 512
    ):
        return None
    return candidate.as_posix()


def _observe_line(line: bytes, inventory: ProjectInventory, observations: Observations) -> None:
    normalized = _normalize_terminal_controls(line)
    if normalized is None:
        observations.parser_complete = False
        _bounded_increment(observations, "parser_incomplete_line_count")
        _bounded_increment(observations, "invalid_control_sequence_count")
        return
    try:
        text = normalized.decode("utf-8", "strict")
    except UnicodeDecodeError:
        observations.parser_complete = False
        _bounded_increment(observations, "parser_incomplete_line_count")
        return
    lowered = text.lower()
    if "comm: file 1 is not in sorted order" in lowered or "comm: file 2 is not in sorted order" in lowered:
        observations.errors.add("package_inventory_ordering")
    if EXPLICIT_COMPILER_FAILURE_RE.search(text):
        observations.errors.add("compiler_failure")
    if any(marker in lowered for marker in ("could not resolve dependencies", "failed to collect dependencies", "could not resolve artifact", "non-resolvable parent pom")):
        observations.errors.add("dependency_resolution")
    if any(marker in lowered for marker in ("unknownhostexception", "name or service not known", "could not resolve host", "temporary failure in name resolution")):
        observations.errors.add("dns_resolution")
    if any(marker in lowered for marker in ("pkix path building failed", "suncertpathbuilderexception", "unable to find valid certification path", "sslhandshakeexception")):
        observations.errors.add("tls_certificate_validation")
    if "no space left on device" in lowered:
        observations.errors.add("disk_space")
    if "outofmemoryerror" in lowered or "java heap space" in lowered:
        observations.errors.add("memory_limit")
    for match in HTTP_RE.finditer(text):
        code = match.group(1)
        observations.errors.add("http_5xx" if code.startswith("5") else f"http_{code}")
    plugin_start = MAVEN_PLUGIN_START_RE.fullmatch(text)
    if plugin_start:
        category = _goal_category(plugin_start.group(1))
        if category:
            observations.plugin_started.add(category)

    reactor_match = REACTOR_FAILURE_RE.fullmatch(text)
    if reactor_match:
        canonical = inventory.canonical_project(" ".join(reactor_match.group(1).split()))
        if canonical:
            observations.reactor_failures.add(canonical)
            observations.projects.add(canonical)
            observations.errors.add("maven_goal_failure")

    goal_match = POM_GOAL_RE.search(text)
    if goal_match:
        plugin_coordinate = goal_match.group(1)
        goal = _goal_category(plugin_coordinate)
        if goal:
            observations.goals.add(goal)
        canonical = inventory.canonical_project(goal_match.group(2))
        if canonical:
            observations.projects.add(canonical)
            observations.failed_goal_projects.add(canonical)
        observations.errors.add("maven_goal_failure")
        if goal == "compiler":
            observations.errors.add("compiler_failure")

    diagnostic = COMPILER_DIAGNOSTIC_RE.fullmatch(text)
    if diagnostic:
        _bounded_increment(observations, "compiler_diagnostic_count")
        observations.errors.add("compiler_failure")
        message = diagnostic.group("message")
        category = _compiler_diagnostic_category(message)
        if category:
            observations.compiler_diagnostic_categories.add(category)
            path_text = diagnostic.group("path")
            relative = _relative_source_path(path_text)
            line_number = int(diagnostic.group("maven_line") or diagnostic.group("javac_line"))
            project = inventory.project_for_source_path(relative) if relative else None
            if project and 1 <= line_number <= 10_000_000:
                observations.projects.add(project)
                location = (relative, line_number, category)
                if location not in observations.diagnostic_locations:
                    if len(observations.diagnostic_locations) < MAX_DIAGNOSTIC_LOCATIONS:
                        observations.diagnostic_locations[location] = None
                    else:
                        observations.diagnostic_locations_truncated = True
                observations.failure_location_identified = bool(observations.diagnostic_locations)
        else:
            _bounded_increment(observations, "unknown_diagnostic_count")
    elif COMPILER_ERROR_MARKER_RE.search(text):
        _bounded_increment(observations, "compiler_diagnostic_count")
        _bounded_increment(observations, "unknown_diagnostic_count")


def _feed_stream(stream: StreamDigest, data: bytes, inventory: ProjectInventory, observations: Observations, line_limit: int) -> bool:
    stream.digest.update(data)
    stream.captured_bytes += len(data)
    pieces = data.split(b"\n")
    if len(pieces) == 1:
        stream.pending.extend(pieces[0])
        if len(stream.pending) > line_limit:
            stream.complete = False
            return False
        return True
    stream.pending.extend(pieces[0])
    if len(stream.pending) > line_limit:
        stream.complete = False
        return False
    _observe_line(bytes(stream.pending), inventory, observations)
    stream.line_count += 1
    stream.pending.clear()
    for piece in pieces[1:-1]:
        if len(piece) > line_limit:
            stream.complete = False
            return False
        _observe_line(piece, inventory, observations)
        stream.line_count += 1
    stream.pending.extend(pieces[-1])
    if len(stream.pending) > line_limit:
        stream.complete = False
        return False
    return True


def _finish_stream(stream: StreamDigest, inventory: ProjectInventory, observations: Observations) -> None:
    if stream.pending:
        _observe_line(bytes(stream.pending), inventory, observations)
        stream.line_count += 1
        stream.pending.clear()


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False


def _terminate_process_group(
    process: subprocess.Popen[bytes], *, term_grace_seconds: float = 8, kill_grace_seconds: float = 5
) -> bool:
    # The group may outlive its parent when a child inherited a pipe. Signal the
    # private process group even if Popen.poll() already observed the leader exit.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return process.poll() is not None
    except OSError:
        _terminate_group_leader(process, kill_grace_seconds)
        return False
    deadline = time.monotonic() + term_grace_seconds
    try:
        while _process_group_exists(process.pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        remains = _process_group_exists(process.pid)
    except OSError:
        _terminate_group_leader(process, kill_grace_seconds)
        return False
    if remains:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return process.poll() is not None
        except OSError:
            _terminate_group_leader(process, kill_grace_seconds)
            return False
        kill_deadline = time.monotonic() + kill_grace_seconds
        try:
            while _process_group_exists(process.pid) and time.monotonic() < kill_deadline:
                time.sleep(0.05)
            remains = _process_group_exists(process.pid)
        except OSError:
            _terminate_group_leader(process, kill_grace_seconds)
            return False
    try:
        process.wait(timeout=max(0.1, kill_grace_seconds))
    except subprocess.TimeoutExpired:
        _terminate_group_leader(process, kill_grace_seconds)
        return False
    except OSError:
        return False
    return not remains


def _terminate_group_leader(process: subprocess.Popen[bytes], wait_seconds: float) -> None:
    """Best-effort stop only the direct owned child when group signaling fails."""
    try:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=max(0.1, wait_seconds))
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=max(0.1, wait_seconds))
        except (OSError, subprocess.TimeoutExpired):
            pass
    except OSError:
        pass


def run_bounded_command(
    argv: list[str],
    *,
    phase: str,
    known_projects: set[str] | ProjectInventory,
    timeout_seconds: float,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_line_bytes: int = MAX_LINE_BYTES,
    cleanup_owned: Callable[[], str] | None = None,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    term_grace_seconds: float = 8,
    kill_grace_seconds: float = 5,
) -> dict[str, object]:
    if phase not in PHASE_DEADLINES or timeout_seconds <= 0 or max_total_bytes <= 0 or max_line_bytes <= 0:
        raise CaptureError("runner_configuration_invalid")
    if isinstance(known_projects, ProjectInventory):
        inventory = known_projects
    else:
        inventory = ProjectInventory(
            projects=set(known_projects),
            aliases={project: {project} for project in known_projects},
            modules=[],
            tracked_paths=set(),
        )
    observations = Observations()
    streams = {"stdout": StreamDigest("stdout"), "stderr": StreamDigest("stderr")}
    total = 0
    timed_out = False
    host_timed_out = False
    process_termination_verified = True
    limit_reason: str | None = None
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    try:
        process = popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            env=_safe_host_environment(),
        )
        assert process.stdout is not None and process.stderr is not None
        for name, handle in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(handle.fileno(), False)
            selector.register(handle, selectors.EVENT_READ, name)
        deadline = time.monotonic() + timeout_seconds
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                host_timed_out = True
                break
            events = selector.select(min(0.2, remaining))
            for key, _ in events:
                name = key.data
                remaining_bytes = max_total_bytes - total
                read_size = min(32768, max(1, remaining_bytes + 1))
                try:
                    chunk = os.read(key.fileobj.fileno(), read_size)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                allowed = min(len(chunk), max(0, remaining_bytes))
                if allowed:
                    kept = chunk[:allowed]
                    total += allowed
                    if not _feed_stream(streams[name], kept, inventory, observations, max_line_bytes):
                        limit_reason = "line_bytes"
                        break
                if len(chunk) > allowed:
                    limit_reason = "total_bytes"
                    break
            if limit_reason:
                break
        if timed_out or limit_reason:
            for stream in streams.values():
                stream.complete = False
            try:
                process_termination_verified = _terminate_process_group(
                    process,
                    term_grace_seconds=term_grace_seconds,
                    kill_grace_seconds=kill_grace_seconds,
                )
            except Exception:
                process_termination_verified = False
            if not process_termination_verified:
                observations.errors.add("process_termination_unverified")
        return_code = process.wait(timeout=15)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        if process is not None:
            try:
                process_termination_verified = _terminate_process_group(
                    process,
                    term_grace_seconds=term_grace_seconds,
                    kill_grace_seconds=kill_grace_seconds,
                )
            except Exception:
                process_termination_verified = False
            if not process_termination_verified:
                observations.errors.add("process_termination_unverified")
        return_code = None
        if limit_reason is None:
            limit_reason = "runner_io"
    finally:
        selector.close()
        if process is not None:
            for handle in (process.stdout, process.stderr):
                if handle:
                    try:
                        handle.close()
                    except OSError:
                        pass

    for stream in streams.values():
        if stream.pending and len(stream.pending) <= max_line_bytes:
            _finish_stream(stream, inventory, observations)
    if return_code == 124:
        timed_out = True
        observations.errors.add("timeout")
    elif return_code in (125, 126, 127):
        observations.errors.add("docker_execution_failure")
    elif return_code is not None and return_code != 0 and not timed_out and not limit_reason and not observations.errors:
        observations.errors.add("nonzero_unclassified")
    if return_code not in (None, 0) and phase == "derived_builder_build" and not observations.errors - {"nonzero_unclassified"}:
        observations.errors.add("docker_build_failure")

    cleanup_status = "not_required"
    if (timed_out or limit_reason or return_code not in (None, 0)) and cleanup_owned is not None:
        try:
            cleanup_status = cleanup_owned()
        except Exception:
            cleanup_status = "unverified"
    if limit_reason:
        result_status = "output_limit" if limit_reason in {"line_bytes", "total_bytes"} else "runner_failure"
    elif timed_out:
        result_status = "timeout"
    elif return_code is None:
        result_status = "runner_failure"
    elif return_code == 0:
        result_status = "success"
    else:
        result_status = "nonzero_exit"
    if not process_termination_verified:
        result_status = "runner_failure"
    if result_status not in ALLOWED_RESULT:
        result_status = "runner_failure"

    def stream_result(stream: StreamDigest) -> dict[str, object]:
        return {
            "captured_bytes": stream.captured_bytes,
            "captured_lines": stream.line_count,
            "sha256": stream.digest.hexdigest(),
            "capture_complete": stream.complete and not host_timed_out and limit_reason is None,
        }

    return {
        "schema_version": 2,
        "parser_schema_version": 1,
        "phase": phase,
        "status": result_status,
        "exit_code": return_code if isinstance(return_code, int) else None,
        "timed_out": timed_out,
        "timeout_source": "host" if host_timed_out else "container" if return_code == 124 else "none",
        "output_limit_reason": limit_reason or "none",
        "stdout": stream_result(streams["stdout"]),
        "stderr": stream_result(streams["stderr"]),
        "error_categories": sorted(error for error in observations.errors if error in ALLOWED_ERROR),
        "project_ids": sorted(observations.projects),
        "failed_goal_project_ids": sorted(observations.failed_goal_projects),
        "reactor_failure_project_ids": sorted(observations.reactor_failures),
        "plugin_started_categories": sorted(observations.plugin_started),
        "goal_categories": sorted(goal for goal in observations.goals if goal in ALLOWED_GOAL),
        "compiler_diagnostic_categories": sorted(
            category for category in observations.compiler_diagnostic_categories
            if category in ALLOWED_COMPILER_DIAGNOSTIC
        ),
        "compiler_diagnostic_count": observations.compiler_diagnostic_count,
        "unknown_diagnostic_count": observations.unknown_diagnostic_count,
        "diagnostic_locations": [
            {"path": path, "line": line_number, "category": category}
            for path, line_number, category in sorted(observations.diagnostic_locations)
        ],
        "diagnostic_location_count": len(observations.diagnostic_locations),
        "diagnostic_locations_truncated": observations.diagnostic_locations_truncated,
        "failure_location_identified": observations.failure_location_identified,
        "parser_complete": observations.parser_complete,
        "parser_incomplete_line_count": observations.parser_incomplete_line_count,
        "invalid_control_sequence_count": observations.invalid_control_sequence_count,
        "diagnostic_counts_saturated": observations.diagnostic_counts_saturated,
        "owned_container_cleanup": cleanup_status,
        "process_termination_verified": process_termination_verified,
        "raw_output_retained": False,
    }


def _phase_command(phase: str) -> tuple[list[str], str | None]:
    if phase == "derived_builder_build":
        return (
            [
                "docker", "build", "--progress=plain", "--pull=false", "--no-cache",
                "--platform", "linux/arm64/v8", "--tag", V4_IMAGE,
                "--file", str(BUILDER_CONTEXT / "Dockerfile"), str(BUILDER_CONTEXT),
            ],
            None,
        )
    container_prefix = [
        "docker", "run", "--rm", "--name", V4_CONTAINER,
        "--label", f"{OWNER_LABEL}={OWNER}", "--label", f"{PHASE_LABEL}={PHASE_LABEL_VALUE}",
        "--platform", "linux/arm64/v8", "--network", "bridge", "--cpus=4", "--memory=8g", "--pids-limit=512",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=2g,mode=0700",
        "--mount", f"type=bind,src={V4_SOURCE},dst=/workspace/source",
        "--mount", f"type=bind,src={V4_OUTPUT},dst=/workspace/output",
        "--mount", f"type=volume,src={V4_CACHE},dst=/root/.m2",
        "--workdir", "/workspace/source", "--env", "MAVEN_OPTS=-Xmx4g",
        "--env", "GIT_CONFIG_COUNT=1", "--env", "GIT_CONFIG_KEY_0=safe.directory",
        "--env", "GIT_CONFIG_VALUE_0=/workspace/source", "--entrypoint", "/bin/sh", V4_IMAGE,
    ]
    if phase == "runtime_module_compile":
        return container_prefix + ["-c", f"timeout --signal=TERM --kill-after=30s {CONTAINER_TIMEOUTS[phase]} ./mvnw -B -Dstyle.color=never -ntp -pl quarkus/runtime -am -DskipTests compile"], V4_CONTAINER
    if phase == "server_distribution_build":
        shell = (
            f"timeout --signal=TERM --kill-after=30s {CONTAINER_TIMEOUTS[phase]} "
            "./mvnw -B -Dstyle.color=never -ntp -pl quarkus/deployment,quarkus/dist -am -DskipTests clean install "
            "&& install -m 0600 quarkus/dist/target/keycloak-26.7.4.zip /workspace/output/keycloak-26.7.4.zip"
        )
        return container_prefix + ["-c", shell], V4_CONTAINER
    raise CaptureError("phase_unknown")


def _cleanup_exact_container(name: str) -> str:
    listing = subprocess.run(
        ["docker", "container", "ls", "--all", "--format", "{{.Names}} {{.Label \"org.picketfence.wp5.owner\"}} {{.Label \"org.picketfence.wp5.phase\"}}", "--filter", f"name=^/{name}$"],
        capture_output=True,
        timeout=10,
        check=False,
        env=_safe_host_environment(),
    )
    if listing.returncode:
        return "unverified"
    rows = [line.decode("ascii", "ignore").strip() for line in listing.stdout.splitlines() if line]
    expected = f"{name} {OWNER} {PHASE_LABEL_VALUE}"
    if not rows:
        return "absent"
    if rows != [expected]:
        return "ownership_mismatch"
    removed = subprocess.run(
        ["docker", "container", "rm", "--force", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
        env=_safe_host_environment(),
    )
    if removed.returncode:
        return "unverified"
    return "removed"


def _phase_receipt_path(phase: str) -> pathlib.Path:
    return pathlib.Path(f"/private/tmp/wp5-as-observer-build-receipt-20261004-v4-{phase}.json")


def _phase_attempt_path(phase: str) -> pathlib.Path:
    return pathlib.Path(f"/private/tmp/wp5-as-observer-build-attempt-20261004-v4-{phase}.json")


def _claim_phase_attempt(phase: str) -> None:
    marker = _phase_attempt_path(phase)
    if marker.exists() or marker.is_symlink():
        raise CaptureError("phase_attempt_already_claimed")
    data = (json.dumps({
        "kind": "wp5-observer-build-v4-phase-attempt",
        "phase": phase,
        "source_commit": PINNED_COMMIT,
        "handler_sha256": HANDLER_AFTER_SHA256,
        "observer_sha256": OBSERVER_SHA256,
        "status": "claimed_once",
    }, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _require_successful_compile_receipt() -> None:
    receipt = _phase_receipt_path("runtime_module_compile")
    try:
        if receipt.is_symlink():
            raise CaptureError("compile_receipt_permissions_invalid")
        metadata = receipt.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o777 != 0o600:
            raise CaptureError("compile_receipt_permissions_invalid")
        data = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise CaptureError("compile_receipt_unavailable") from None
    stdout = data.get("stdout")
    stderr = data.get("stderr")
    if (
        data.get("schema_version") != 2
        or data.get("parser_schema_version") != 1
        or data.get("phase") != "runtime_module_compile"
        or data.get("status") != "success"
        or data.get("source_commit") != PINNED_COMMIT
        or data.get("exit_code") != 0
        or data.get("timed_out") is not False
        or data.get("output_limit_reason") != "none"
        or data.get("parser_complete") is not True
        or data.get("parser_incomplete_line_count") != 0
        or data.get("invalid_control_sequence_count") != 0
        or data.get("diagnostic_counts_saturated") is not False
        or data.get("compiler_diagnostic_count") != 0
        or data.get("unknown_diagnostic_count") != 0
        or data.get("failure_location_identified") is not False
        or data.get("diagnostic_locations") != []
        or data.get("diagnostic_locations_truncated") is not False
        or data.get("failed_goal_project_ids") != []
        or data.get("reactor_failure_project_ids") != []
        or data.get("error_categories") != []
        or data.get("goal_categories") != []
        or not isinstance(stdout, dict)
        or stdout.get("capture_complete") is not True
        or not isinstance(stderr, dict)
        or stderr.get("capture_complete") is not True
    ):
        raise CaptureError("compile_receipt_not_success")
    if data.get("observer_sha256") != OBSERVER_SHA256 or data.get("handler_sha256") != HANDLER_AFTER_SHA256:
        raise CaptureError("compile_receipt_source_mismatch")


def _write_phase_receipt(record: dict[str, object], source: pathlib.Path, phase: str) -> None:
    path = _phase_receipt_path(phase)
    if path.exists() or path.is_symlink():
        raise CaptureError("phase_receipt_already_exists")
    payload = {
        **record,
        "source_commit": PINNED_COMMIT,
        "handler_sha256": HANDLER_AFTER_SHA256,
        "observer_sha256": OBSERVER_SHA256,
        "source_path": str(source),
        "phase_receipt_path": str(path),
    }
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=sorted(PHASE_DEADLINES))
    parser.add_argument("--source", type=pathlib.Path, default=V4_SOURCE)
    args = parser.parse_args(argv)
    try:
        if args.source.resolve(strict=True) != V4_SOURCE:
            raise CaptureError("source_path_mismatch")
        phase_receipt = _phase_receipt_path(args.phase)
        phase_attempt = _phase_attempt_path(args.phase)
        if phase_receipt.exists() or phase_receipt.is_symlink() or phase_attempt.exists() or phase_attempt.is_symlink():
            raise CaptureError("phase_receipt_already_exists")
        projects = _project_ids_from_poms(args.source)
        if args.phase == "server_distribution_build":
            _require_successful_compile_receipt()
        command, container_name = _phase_command(args.phase)
        timeout_seconds = PHASE_DEADLINES[args.phase]
        _claim_phase_attempt(args.phase)
        result = run_bounded_command(
            command,
            phase=args.phase,
            known_projects=projects,
            timeout_seconds=timeout_seconds,
            cleanup_owned=(lambda: _cleanup_exact_container(container_name)) if container_name else None,
        )
        _write_phase_receipt(result, args.source, args.phase)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result["status"] == "success" else 1
    except CaptureError as error:
        result = {
            "schema_version": 2,
            "phase": args.phase,
            "status": "runner_failure",
            "reason": error.reason,
            "raw_output_retained": False,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 2
    except Exception:
        # Do not expose exception text, traceback, path, or environment.
        print(json.dumps({"schema_version": 2, "phase": args.phase, "status": "runner_failure", "reason": "unexpected_runner_failure", "raw_output_retained": False}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
