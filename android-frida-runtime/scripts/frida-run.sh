#!/usr/bin/env bash
# Spawn-first Frida launcher for protected Android applications.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  frida-run.sh --package PKG --script HOOK.js [--bridge-bundle BRIDGE.js]
               [--usb | --remote HOST:PORT] --expected-version VERSION
               [--pause] [--dry-run]
  frida-run.sh --attach --process NAME --script HOOK.js [connection options]
  frida-run.sh --list-devices
  frida-run.sh --list-processes [--usb | --remote HOST:PORT]

Spawn is the default. Attach is explicit and unsafe for a Java bridge on protected apps.
EOF
}

need_value() {
    [[ $# -ge 2 && -n "$2" ]] || { echo "ERR: $1 requires a value" >&2; exit 2; }
}

PACKAGE=""
PROCESS=""
REMOTE_HOST="127.0.0.1:27042"
SCRIPT_PATH=""
BRIDGE_BUNDLE=""
EXPECTED_VERSION="${FRIDA_EXPECTED_VERSION:-}"
USB=false
SPAWN=true
PAUSE=false
LIST_DEVICES=false
LIST_PROCESSES=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --package|-p) need_value "$@"; PACKAGE="$2"; shift 2 ;;
        --process) need_value "$@"; PROCESS="$2"; shift 2 ;;
        --remote|-H) need_value "$@"; REMOTE_HOST="$2"; shift 2 ;;
        --script|-l) need_value "$@"; SCRIPT_PATH="$2"; shift 2 ;;
        --bridge-bundle) need_value "$@"; BRIDGE_BUNDLE="$2"; shift 2 ;;
        --expected-version) need_value "$@"; EXPECTED_VERSION="$2"; shift 2 ;;
        --usb|-U) USB=true; shift ;;
        --spawn|-f) SPAWN=true; shift ;;
        --attach) SPAWN=false; shift ;;
        --pause) PAUSE=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --list-devices) LIST_DEVICES=true; shift ;;
        --list-processes) LIST_PROCESSES=true; shift ;;
        --help|-h) usage; exit 0 ;;
        -*) echo "ERR: unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) echo "ERR: unexpected argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

command -v frida &>/dev/null || {
    echo "ERR: frida unavailable; install a client matching the server exactly" >&2
    exit 1
}
CLIENT_VERSION="$(frida --version)"
if [[ -n "$EXPECTED_VERSION" && "$CLIENT_VERSION" != "$EXPECTED_VERSION" ]]; then
    echo "ERR: Frida client $CLIENT_VERSION != expected server $EXPECTED_VERSION" >&2
    exit 1
fi

if [[ "$LIST_DEVICES" == "true" ]]; then
    frida-ls-devices
    exit 0
fi

connection_args=()
process_args=()
if [[ "$USB" == "true" ]]; then
    connection_args+=("-U")
    process_args+=("-U")
else
    connection_args+=("-H" "$REMOTE_HOST")
    process_args+=("-H" "$REMOTE_HOST")
fi

if [[ "$LIST_PROCESSES" == "true" ]]; then
    frida-ps "${process_args[@]}"
    exit 0
fi

if [[ "$SPAWN" == "true" ]]; then
    [[ -n "$PACKAGE" ]] || { echo "ERR: spawn requires --package" >&2; exit 2; }
    [[ -z "$PROCESS" ]] || { echo "ERR: --process is attach-only" >&2; exit 2; }
    TARGET="$PACKAGE"
else
    TARGET="${PROCESS:-$PACKAGE}"
    [[ -n "$TARGET" ]] || { echo "ERR: attach requires --process or --package" >&2; exit 2; }
    [[ "$PAUSE" == "false" ]] || { echo "ERR: --pause only applies to spawn" >&2; exit 2; }
    echo "WARN: attach selected; do not attach a Java bridge to a running protected app" >&2
fi

[[ -n "$SCRIPT_PATH" && -f "$SCRIPT_PATH" ]] || {
    echo "ERR: Frida script not found: ${SCRIPT_PATH:-<unset>}" >&2
    exit 1
}
if [[ -n "$BRIDGE_BUNDLE" && ! -f "$BRIDGE_BUNDLE" ]]; then
    echo "ERR: bridge bundle not found: $BRIDGE_BUNDLE" >&2
    exit 1
fi

LOAD_SCRIPT="$SCRIPT_PATH"
COMBINED_SCRIPT=""
cleanup() { [[ -z "$COMBINED_SCRIPT" ]] || rm -f "$COMBINED_SCRIPT"; }
trap cleanup EXIT
if [[ -n "$BRIDGE_BUNDLE" ]]; then
    COMBINED_SCRIPT="$(mktemp --suffix=.js)"
    cat "$BRIDGE_BUNDLE" "$SCRIPT_PATH" > "$COMBINED_SCRIPT"
    LOAD_SCRIPT="$COMBINED_SCRIPT"
fi

frida_args=("${connection_args[@]}")
if [[ "$SPAWN" == "true" ]]; then
    frida_args+=("-f" "$TARGET")
    [[ "$PAUSE" == "false" ]] || frida_args+=("--pause")
else
    frida_args+=("-n" "$TARGET")
fi
frida_args+=("-l" "$LOAD_SCRIPT")

printf 'mode=%s\n' "$([[ "$SPAWN" == "true" ]] && echo spawn || echo attach)"
printf 'client_version=%s\n' "$CLIENT_VERSION"
printf 'expected_server_version=%s\n' "${EXPECTED_VERSION:-<not supplied>}"

if [[ "$DRY_RUN" == "true" ]]; then
    printf 'command='
    printf '%q ' frida "${frida_args[@]}"
    printf '\n'
    exit 0
fi

if [[ "$USB" == "true" ]]; then
    frida-ps -U >/dev/null
else
    frida-ps -H "$REMOTE_HOST" >/dev/null
fi
frida "${frida_args[@]}"
