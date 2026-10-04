#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
WP5 local demo readiness gate

scripts/require-wp5-readiness.sh --preview
scripts/require-wp5-readiness.sh --wait [--timeout SECONDS] [--interval SECONDS]
FAPI_DEMO_PROXY_LISTEN='0.0.0.0:8443 ssl' scripts/require-wp5-readiness.sh \
    --supervise [--timeout SECONDS] [--interval SECONDS]

--wait reads the current third-party Data Plane worker snapshots and does not
start, stop, restart, apply, sync, or open a demo entrypoint. --supervise writes
the local all-worker marker after readiness passes, opens a loopback-only TCP
forward from 127.0.0.1:8443 to the DP's private 127.0.0.1:18443 mapping, then
starts the UI. On any later mismatch it removes the marker, closes the forward,
and stops both the UI and third-party Data Plane. It never starts or restarts a
Data Plane.
EOF
}

if [[ "${1:-}" == "--preview" ]]; then
  cat <<'EOF'
The normal `make up` path remains closed. After the isolated WP5 runtime review
and explicit normal-runtime approval, the intended local sequence is:

  FAPI_DEMO_PROXY_LISTEN='0.0.0.0:8443 ssl' docker compose --env-file .env --env-file .generated/runtime.env --profile gateway up -d kong-third-party
  scripts/require-wp5-readiness.sh --wait --timeout 120
  FAPI_DEMO_PROXY_LISTEN='0.0.0.0:8443 ssl' scripts/require-wp5-readiness.sh --supervise

The first command starts only the third-party Data Plane. Its Kong listener is
explicitly enabled for the demo but published only on loopback port 18443. The
ordinary browser entry on loopback port 8443 remains closed until every current
worker matches the fixed route manifest and the supervisor creates the local
all-worker marker. The supervisor then opens the opaque TCP forward and UI;
worker, generation, registry, bridge, or config drift removes the marker, closes
the forward, and stops both services.
EOF
  exit 0
fi

mode="${1:-}"
if [[ "$mode" != "--wait" && "$mode" != "--supervise" ]]; then
  echo "make up is unavailable until WP5 runtime readiness and entrypoint checks are accepted" >&2
  usage >&2
  exit 1
fi
shift

timeout_seconds=120
interval_seconds=2
while (($#)); do
  case "$1" in
    --timeout)
      (($# >= 2)) || { echo "--timeout requires seconds" >&2; exit 2; }
      timeout_seconds="$2"
      shift 2
      ;;
    --interval)
      (($# >= 2)) || { echo "--interval requires seconds" >&2; exit 2; }
      interval_seconds="$2"
      shift 2
      ;;
    *)
      echo "unsupported readiness option" >&2
      exit 2
      ;;
  esac
done
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ && "$interval_seconds" =~ ^[1-9][0-9]*$ ]] || {
  echo "timeout and interval must be positive whole seconds" >&2
  exit 2
}

if [[ "$mode" == "--supervise" && "${FAPI_DEMO_PROXY_LISTEN:-}" != "0.0.0.0:8443 ssl" ]]; then
  echo "supervise requires the explicit local 3rd-party listener setting" >&2
  exit 2
fi

compose_args=(--project-directory "$ROOT")
[[ -f "$ROOT/.env" ]] && compose_args+=(--env-file "$ROOT/.env")
[[ -f "$ROOT/.generated/runtime.env" ]] && compose_args+=(--env-file "$ROOT/.generated/runtime.env")

compose() {
  docker compose "${compose_args[@]}" --profile gateway --profile demo "$@"
}

container_id() {
  local ids
  ids="$(compose ps --quiet --all kong-third-party 2>/dev/null)" || return 1
  [[ "$ids" =~ ^[0-9a-fA-F]{64}$ ]] || return 1
  printf '%s\n' "$ids"
}

container_running() {
  [[ "$(docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null)" == "true" ]]
}

capture_worker_state() {
  docker exec "$1" /bin/sh -ec '
    status_dir="${FAPI_AS_TRANSPORT_STATUS_DIR:-/run/kong/fapi-transport-ready}"
    generation_file="$status_dir/generation"
    [ -r "$generation_file" ] && [ "$(stat -c %a "$status_dir")" = 700 ]
    [ "$(stat -c %u "$status_dir")" = "$(id -u)" ]
    [ "$(stat -c %a "$generation_file")" = 600 ]
    [ "$(stat -c %u "$generation_file")" = "$(id -u)" ]
    generation="$(cat "$generation_file")"
    case "$generation" in ""|*[!A-Za-z0-9._-]*) exit 21 ;; esac
    printf "G\t%s\n" "$generation"

    prefix="${KONG_PREFIX:-/usr/local/kong}"
    master_file="$prefix/pids/nginx.pid"
    [ -r "$master_file" ] || exit 22
    master="$(cat "$master_file")"
    case "$master" in ""|*[!0-9]*) exit 23 ;; esac
    children="$(cat "/proc/$master/task/$master/children")"
    for pid in $children; do
      [ -r "/proc/$pid/cmdline" ] || continue
      command_line="$(tr "\000" " " < "/proc/$pid/cmdline")"
      case "$command_line" in
        *"nginx: worker process"*) printf "P\t%s\n" "$pid" ;;
      esac
    done

    for status_file in "$status_dir"/worker-*.json; do
      [ -f "$status_file" ] || continue
      [ "$(stat -c %a "$status_file")" = 600 ] || exit 24
      [ "$(stat -c %u "$status_file")" = "$(id -u)" ] || exit 25
      printf "S\t%s\t" "${status_file##*/}"
      cat "$status_file"
      printf "\n"
    done
  ' 2>/dev/null
}

image_has_required_plugins() {
  docker exec "$1" /bin/sh -ec '
    [ "${KONG_PLUGINS:-}" = "bundled,fapi-as-mtls-transport,fapi-client-auth-bridge" ]
    test -s /usr/local/share/lua/5.1/kong/plugins/fapi-as-mtls-transport/handler.lua
    test -s /usr/local/share/lua/5.1/kong/plugins/fapi-as-mtls-transport/schema.lua
    test -s /usr/local/share/lua/5.1/kong/plugins/fapi-client-auth-bridge/handler.lua
    test -s /usr/local/share/lua/5.1/kong/plugins/fapi-client-auth-bridge/schema.lua
  ' >/dev/null 2>&1
}

validator="$(cat <<'PY'
import hashlib
import json
import re
import sys

expected_generation = sys.argv[1]
expected_routes = [
    {"route_id": "0f45debe-a3a6-5207-aea3-637227fb96f2", "logical_route": "B", "client_id": "third-party-fapi-pkj-mtls"},
    {"route_id": "754519ff-b0b9-5ed5-94c0-e453d260c6c4", "logical_route": "A", "client_id": "third-party-fapi-mtls"},
]
expected_routes.sort(key=lambda route: route["route_id"])
allowed = {"worker_id", "pid", "generation", "config_hash", "registry_epoch", "wrapper_ready", "registry_ready", "bridge_loaded", "delegate_ready", "routes"}
generation = None
worker_pids = set()
rows = []

for line in sys.stdin:
    kind, sep, remainder = line.rstrip("\n").partition("\t")
    if not sep:
        raise SystemExit(1)
    if kind == "G":
        if generation is not None:
            raise SystemExit(1)
        generation = remainder
    elif kind == "P":
        value = remainder
        if not value.isdecimal() or int(value) < 1 or int(value) in worker_pids:
            raise SystemExit(1)
        worker_pids.add(int(value))
    elif kind == "S":
        filename, filename_sep, value = remainder.partition("\t")
        if not filename_sep:
            raise SystemExit(1)
        try:
            row = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            raise SystemExit(1)
        if not isinstance(row, dict) or set(row) != allowed:
            raise SystemExit(1)
        rows.append((filename, row))
    else:
        raise SystemExit(1)

if not generation or generation != expected_generation or not worker_pids or not rows:
    raise SystemExit(1)

current = []
seen_worker_ids = set()
hashes = set()
for filename, row in rows:
    worker_id = row["worker_id"]
    if isinstance(worker_id, bool) or not isinstance(worker_id, int) or worker_id < 0:
        raise SystemExit(1)
    if worker_id in seen_worker_ids:
        raise SystemExit(1)
    seen_worker_ids.add(worker_id)
    if filename != "worker-" + str(worker_id) + ".json":
        raise SystemExit(1)
    pid = row["pid"]
    if isinstance(pid, bool) or not isinstance(pid, int) or pid not in worker_pids:
        continue  # stale status from a prior worker cannot satisfy coverage
    if row["generation"] != generation:
        raise SystemExit(1)
    config_hash = row["config_hash"]
    epoch = row["registry_epoch"]
    if not isinstance(config_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", config_hash):
        raise SystemExit(1)
    if not isinstance(epoch, str) or not re.fullmatch(r"[0-9a-f]{64}", epoch):
        raise SystemExit(1)
    hashes.add(config_hash)
    if any(row[key] is not True for key in ("wrapper_ready", "registry_ready", "bridge_loaded", "delegate_ready")):
        raise SystemExit(1)
    routes = row["routes"]
    if not isinstance(routes, list) or not all(isinstance(route, dict) for route in routes):
        raise SystemExit(1)
    if any(set(route) != {"route_id", "logical_route", "client_id"} for route in routes):
        raise SystemExit(1)
    if sorted(routes, key=lambda route: route["route_id"]) != expected_routes:
        raise SystemExit(1)
    current.append({"worker_id": worker_id, "pid": pid, "registry_epoch": epoch})

if len(hashes) != 1 or {row["pid"] for row in current} != worker_pids:
    raise SystemExit(1)

marker = {
    "generation": generation,
    "config_hash": next(iter(hashes)),
    "workers": sorted(current, key=lambda row: row["worker_id"]),
}
fingerprint_source = json.dumps(
    {"generation": generation, "config_hash": next(iter(hashes)), "routes": expected_routes, "workers": marker["workers"]},
    sort_keys=True,
    separators=(",", ":"),
).encode()
print(hashlib.sha256(fingerprint_source).hexdigest())
print(json.dumps(marker, sort_keys=True, separators=(",", ":")))
PY
)"

CURRENT_CONTAINER_ID=""
CURRENT_FINGERPRINT=""
CURRENT_GENERATION=""
CURRENT_MARKER=""
forwarder_pid=""
forwarder_log=""

check_container_identity() {
  local found
  found="$(container_id)" || return 1
  [[ "$found" == "$CURRENT_CONTAINER_ID" ]] || return 1
  container_running "$CURRENT_CONTAINER_ID" && image_has_required_plugins "$CURRENT_CONTAINER_ID"
}

check_ready_once() {
  local snapshot validation generation fingerprint
  check_container_identity || return 1
  snapshot="$(capture_worker_state "$CURRENT_CONTAINER_ID")" || return 1
  generation="$(printf '%s\n' "$snapshot" | awk -F '\t' '$1 == "G" {print $2; exit}')"
  [[ -n "$generation" ]] || return 1
  validation="$(printf '%s\n' "$snapshot" | python3 -c "$validator" "$generation" 2>/dev/null)" || return 1
  fingerprint="${validation%%$'\n'*}"
  CURRENT_MARKER="${validation#*$'\n'}"
  [[ -n "$CURRENT_MARKER" && "$CURRENT_MARKER" != *$'\n'* ]] || return 1
  if [[ -n "$CURRENT_GENERATION" && "$CURRENT_GENERATION" != "$generation" ]]; then
    return 1
  fi
  CURRENT_GENERATION="$generation"
  CURRENT_FINGERPRINT="$fingerprint"
}

wait_for_ready() {
  local deadline now snapshot generation
  CURRENT_CONTAINER_ID="$(container_id)" || {
    echo "third-party Data Plane container is unavailable" >&2
    return 1
  }
  container_running "$CURRENT_CONTAINER_ID" || {
    echo "third-party Data Plane is not running" >&2
    return 1
  }
  deadline=$(( $(date +%s) + timeout_seconds ))
  while true; do
    check_container_identity || {
      echo "third-party Data Plane changed or stopped; run a fresh readiness check" >&2
      return 1
    }
    snapshot="$(capture_worker_state "$CURRENT_CONTAINER_ID")" || snapshot=""
    generation="$(printf '%s\n' "$snapshot" | awk -F '\t' '$1 == "G" {print $2; exit}')"
    if [[ -n "$generation" ]]; then
      if [[ -n "$CURRENT_GENERATION" && "$CURRENT_GENERATION" != "$generation" ]]; then
        echo "third-party Data Plane restarted; run a fresh readiness check" >&2
        return 1
      fi
      CURRENT_GENERATION="$generation"
      local validation
      validation="$(printf '%s\n' "$snapshot" | python3 -c "$validator" "$CURRENT_GENERATION" 2>/dev/null)" || validation=""
      if [[ -n "$validation" ]]; then
        CURRENT_FINGERPRINT="${validation%%$'\n'*}"
        CURRENT_MARKER="${validation#*$'\n'}"
        echo "WP5 worker readiness accepted"
        return 0
      fi
    fi
    now="$(date +%s)"
    if ((now >= deadline)); then
      echo "WP5 readiness timed out; UI remains closed" >&2
      return 1
    fi
    sleep "$interval_seconds"
  done
}

remove_ready_marker() {
  [[ -n "$CURRENT_CONTAINER_ID" ]] || return 0
  docker exec "$CURRENT_CONTAINER_ID" /bin/sh -ec '
    status_dir="${FAPI_AS_TRANSPORT_STATUS_DIR:-/run/kong/fapi-transport-ready}"
    rm -f "$status_dir/ready.json"
  ' >/dev/null 2>&1 || true
}

publish_ready_marker() {
  [[ -n "$CURRENT_MARKER" ]] || return 1
  printf '%s' "$CURRENT_MARKER" | docker exec -i "$CURRENT_CONTAINER_ID" /bin/sh -ec '
    status_dir="${FAPI_AS_TRANSPORT_STATUS_DIR:-/run/kong/fapi-transport-ready}"
    [ "$(stat -c %a "$status_dir")" = 700 ]
    [ "$(stat -c %u "$status_dir")" = "$(id -u)" ]
    umask 077
    temp="$status_dir/ready.json.tmp-$$"
    trap '\''rm -f "$temp"'\'' EXIT HUP INT TERM
    cat > "$temp"
    chmod 0600 "$temp"
    mv -f "$temp" "$status_dir/ready.json"
    [ "$(stat -c %a "$status_dir/ready.json")" = 600 ]
    [ "$(stat -c %u "$status_dir/ready.json")" = "$(id -u)" ]
  ' >/dev/null 2>&1
}

stop_forwarder() {
  if [[ -n "$forwarder_pid" ]]; then
    kill -TERM "$forwarder_pid" >/dev/null 2>&1 || true
    wait "$forwarder_pid" >/dev/null 2>&1 || true
    forwarder_pid=""
  fi
  if [[ -n "$forwarder_log" ]]; then
    rm -f "$forwarder_log"
    forwarder_log=""
  fi
}

start_forwarder() {
  local tries
  umask 077
  forwarder_log="$(mktemp "${TMPDIR:-/tmp}/wp5-forward.XXXXXX")" || return 1
  python3 "$ROOT/scripts/wp5-demo-forward.py" \
    --listen-host 127.0.0.1 --listen-port 8443 \
    --target-host 127.0.0.1 --target-port 18443 \
    >"$forwarder_log" 2>&1 &
  forwarder_pid=$!
  for tries in 1 2 3 4 5 6 7 8 9 10; do
    if /usr/bin/grep -Fqx 'WP5 local TCP forward active' "$forwarder_log"; then
      return 0
    fi
    if ! kill -0 "$forwarder_pid" >/dev/null 2>&1; then
      /bin/cat "$forwarder_log" >&2
      stop_forwarder
      return 1
    fi
    sleep 1
  done
  echo "WP5 local TCP forward did not become ready" >&2
  stop_forwarder
  return 1
}

close_demo_entry() {
  remove_ready_marker
  stop_forwarder
  compose stop ui kong-third-party >/dev/null 2>&1 || true
}

if [[ "$mode" == "--wait" ]]; then
  wait_for_ready
  exit $?
fi

trap 'close_demo_entry; exit 130' INT TERM HUP
CURRENT_CONTAINER_ID="$(container_id)" || {
  echo "third-party Data Plane container is unavailable" >&2
  exit 1
}
container_running "$CURRENT_CONTAINER_ID" || {
  echo "third-party Data Plane is not running" >&2
  exit 1
}
remove_ready_marker
if ! wait_for_ready; then
  close_demo_entry
  exit 1
fi

# Re-read after the wait, publish the snapshot, and require another full proof
# before opening either local entry. A worker restart also removes this marker
# inside Kong, so AS traffic remains fail-closed during the polling interval.
if ! check_ready_once; then
  close_demo_entry
  echo "WP5 readiness changed before entry could open" >&2
  exit 1
fi
accepted_fingerprint="$CURRENT_FINGERPRINT"
if ! publish_ready_marker || ! check_ready_once || [[ "$CURRENT_FINGERPRINT" != "$accepted_fingerprint" ]]; then
  close_demo_entry
  echo "WP5 all-worker marker could not be confirmed; entry remains closed" >&2
  exit 1
fi
if ! start_forwarder; then
  close_demo_entry
  exit 1
fi
if ! check_ready_once || [[ "$CURRENT_FINGERPRINT" != "$accepted_fingerprint" ]]; then
  close_demo_entry
  echo "WP5 readiness changed before entry could open" >&2
  exit 1
fi

compose up --detach --no-deps --no-build ui >/dev/null || {
  close_demo_entry
  echo "UI could not be started after readiness passed" >&2
  exit 1
}
if ! check_ready_once || [[ "$CURRENT_FINGERPRINT" != "$accepted_fingerprint" ]]; then
  close_demo_entry
  echo "WP5 readiness changed while the UI was opening" >&2
  exit 1
fi
echo "WP5 local demo supervisor active; Ctrl-C closes the UI and third-party entry"
while true; do
  sleep "$interval_seconds"
  if ! kill -0 "$forwarder_pid" >/dev/null 2>&1; then
    close_demo_entry
    echo "WP5 local forward stopped; UI and third-party entry are closed" >&2
    exit 1
  fi
  fingerprint_before="$CURRENT_FINGERPRINT"
  if ! check_ready_once || [[ "$CURRENT_FINGERPRINT" != "$fingerprint_before" ]]; then
    close_demo_entry
    echo "WP5 readiness changed; UI and third-party entry are closed" >&2
    exit 1
  fi
done
