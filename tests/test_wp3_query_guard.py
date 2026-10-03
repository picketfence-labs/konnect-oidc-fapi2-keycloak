#!/usr/bin/env python3
"""Execute the reviewed inline API pre-function against bounded fake PDK inputs."""

from __future__ import annotations

import shutil
import subprocess
import unittest
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
LUAJIT = shutil.which("luajit")


def load_access_script() -> str:
    source = (ROOT / "kong/api-gateway.yaml").read_text(encoding="utf-8")
    rendered = re.sub(
        r'\$\{\{\s*env\s+"([A-Z0-9_]+)"\s*\}\}',
        lambda match: f"deck-template:{match.group(1)}",
        source,
    )
    state = yaml.safe_load(rendered)
    plugins = [item for item in state["plugins"] if item.get("name") == "pre-function"]
    if len(plugins) != 1:
        raise AssertionError("expected exactly one API pre-function")
    access = plugins[0]["config"]["access"]
    if len(access) != 1 or not isinstance(access[0], str):
        raise AssertionError("expected one inline API pre-function source")
    return access[0]


ACCESS = load_access_script()


def run_lua_case(query_setup: str, *, expected_status: int | None):
    if LUAJIT is None:
        raise AssertionError("luajit is required for the repo's Lua plugin tests")
    source = f"""
local response_status = nil
local response_header = nil
local query_mode = "normal"
local get_query_result = nil
local get_query_error = nil
kong = {{
  request = {{
    get_headers = function(limit) assert(limit == 1000); return {{}} end,
    get_query = function(limit)
      assert(limit == 1000)
      if query_mode == "throw" then error("FIXED_TEST_ERROR") end
      return get_query_result, get_query_error
    end,
  }},
  response = {{
    set_header = function(name, value)
      assert(name == "WWW-Authenticate")
      response_header = value
    end,
    exit = function(status, body)
      response_status = status
      return {{status = status, body = body}}
    end,
  }},
  service = {{request = {{clear_header = function(_name) end}}}},
}}
{query_setup}
local access = function()
{ACCESS}
end
local result = access()
"""
    if expected_status is None:
        source += "assert(result == nil); assert(response_status == nil); assert(response_header == nil)\n"
    else:
        source += (
            f"assert(type(result) == 'table' and result.status == {expected_status})\n"
            f"assert(response_status == {expected_status})\n"
            "assert(response_header == 'Bearer error=\"invalid_token\"')\n"
            "assert(result.body.message == 'Invalid access token')\n"
        )
    result = subprocess.run(
        [LUAJIT, "-"], input=source, text=True, capture_output=True, check=False, timeout=5,
    )
    if result.returncode != 0:
        raise AssertionError("inline pre-function mock failed its fixed contract")


class QueryGuardTests(unittest.TestCase):
    def test_no_query_and_harmless_values_continue(self):
        run_lua_case("get_query_result = {}; get_query_error = nil", expected_status=None)
        run_lua_case('get_query_result = {probe = "harmless"}; get_query_error = nil', expected_status=None)
        run_lua_case('get_query_result = {x = true}; get_query_error = nil', expected_status=None)

    def test_decoded_case_dash_and_underscore_access_token_names_reject(self):
        for name in ("access_token", "access-token", "ACCESS_TOKEN"):
            with self.subTest(name=name):
                run_lua_case(
                    f'get_query_result = {{["{name}"] = "TOKEN_SENTINEL_VALUE"}}; get_query_error = nil',
                    expected_status=401,
                )

    def test_duplicate_query_token_name_rejects_without_reading_token_value(self):
        run_lua_case(
            'get_query_result = {access_token = {"TOKEN_SENTINEL_FIRST", "TOKEN_SENTINEL_SECOND"}}; get_query_error = nil',
            expected_status=401,
        )

    def test_999_harmless_occurrences_continue_and_1000_fail_closed(self):
        run_lua_case(
            'local values = {}; for i = 1, 999 do values[i] = "x" end; get_query_result = {x = values}; get_query_error = nil',
            expected_status=None,
        )
        run_lua_case(
            'local values = {}; for i = 1, 1000 do values[i] = "x" end; get_query_result = {x = values}; get_query_error = nil',
            expected_status=401,
        )

    def test_query_error_nil_and_malformed_shapes_fail_closed(self):
        cases = (
            ('query_mode = "throw"; get_query_result = {}; get_query_error = nil', 401),
            ("get_query_result = nil; get_query_error = 'truncated'", 401),
            ("get_query_result = {x = 'harmless'}; get_query_error = 'truncated'", 401),
            ("get_query_result = nil; get_query_error = nil", 401),
            ("get_query_result = 'not-a-table'; get_query_error = nil", 401),
            ("get_query_result = {[true] = 'bad-name'}; get_query_error = nil", 401),
            ('get_query_result = {x = function() end}; get_query_error = nil', 401),
            ('get_query_result = {x = {[1] = "a", [3] = "b"}}; get_query_error = nil', 401),
        )
        for setup, status in cases:
            with self.subTest(setup=setup.split(";", 1)[0]):
                run_lua_case(setup, expected_status=status)


if __name__ == "__main__":
    unittest.main()
