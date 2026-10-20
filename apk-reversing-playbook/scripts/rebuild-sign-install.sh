#!/usr/bin/env bash
# Rebuild, align, sign, verify, and optionally install one APK.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: rebuild-sign-install.sh APKTOOL_PROJECT --keystore PATH [options]
  --out DIR          Output directory (default: project parent)
  --name NAME        Output filename prefix
  --keystore PATH    Existing analysis keystore
  --zipalign PATH    Explicit zipalign binary
  --apksigner PATH   Explicit apksigner executable or JAR
  --alias NAME       Key alias (default: androiddebugkey)
  --store-pass PASS  Keystore password (default: android or REBUILD_STORE_PASS)
  --key-pass PASS    Key password (default: android or REBUILD_KEY_PASS)

Prefer the environment for non-default credentials: REBUILD_STORE_PASS and
REBUILD_KEY_PASS keep passwords out of process arguments; --store-pass and
--key-pass override them when passed explicitly.

  --install          Install the signed APK
  --reinstall        adb install -r; only when the installed signer matches
  --device SERIAL    Target device
  --clean            Remove previous generated APKs first

This helper handles one rebuilt APK, never uninstalls an app, and does not create keys.
EOF
}

need_value() {
    [[ $# -ge 2 && -n "$2" ]] || { echo "ERR: $1 requires a value" >&2; exit 2; }
}

find_sdk_tool() {
    local name="$1" root candidate=""
    for root in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}"; do
        [[ -n "$root" && -d "$root/build-tools" ]] || continue
        candidate="$(find "$root/build-tools" -mindepth 2 -maxdepth 2 -type f \
            -name "$name" -perm -u+x 2>/dev/null | sort -V | tail -1)"
        [[ -z "$candidate" ]] || { printf '%s\n' "$candidate"; return 0; }
    done
    return 1
}

PROJECT_DIR=""
OUT_DIR=""
BASE_NAME=""
KEYSTORE="${ANDROID_DEBUG_KEYSTORE:-}"
KEY_ALIAS="androiddebugkey"
STORE_PASS="${REBUILD_STORE_PASS:-android}"
KEY_PASS="${REBUILD_KEY_PASS:-android}"
ZIPALIGN_BIN="${ZIPALIGN:-}"
APKSIGNER_PATH="${APKSIGNER:-${APKSIGNER_JAR:-}}"
DEVICE_SERIAL=""
DO_INSTALL=false
REINSTALL=false
CLEAN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) need_value "$@"; OUT_DIR="$2"; shift 2 ;;
        --name) need_value "$@"; BASE_NAME="$2"; shift 2 ;;
        --keystore) need_value "$@"; KEYSTORE="$2"; shift 2 ;;
        --alias) need_value "$@"; KEY_ALIAS="$2"; shift 2 ;;
        --store-pass) need_value "$@"; STORE_PASS="$2"; shift 2 ;;
        --key-pass) need_value "$@"; KEY_PASS="$2"; shift 2 ;;
        --zipalign) need_value "$@"; ZIPALIGN_BIN="$2"; shift 2 ;;
        --apksigner) need_value "$@"; APKSIGNER_PATH="$2"; shift 2 ;;
        --device) need_value "$@"; DEVICE_SERIAL="$2"; shift 2 ;;
        --install) DO_INSTALL=true; shift ;;
        --reinstall) REINSTALL=true; DO_INSTALL=true; shift ;;
        --clean) CLEAN=true; shift ;;
        --help|-h) usage; exit 0 ;;
        -*) echo "ERR: unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) [[ -z "$PROJECT_DIR" ]] || { echo "ERR: multiple project directories supplied" >&2; exit 2; }
           PROJECT_DIR="$1"; shift ;;
    esac
done

[[ -n "$PROJECT_DIR" && -d "$PROJECT_DIR" ]] || { usage >&2; exit 2; }
command -v apktool &>/dev/null || { echo "ERR: apktool unavailable" >&2; exit 1; }
[[ "$DO_INSTALL" == "false" ]] || command -v adb &>/dev/null || { echo "ERR: adb unavailable" >&2; exit 1; }

if [[ -z "$ZIPALIGN_BIN" ]]; then
    ZIPALIGN_BIN="$(command -v zipalign || find_sdk_tool zipalign || true)"
fi
[[ -n "$ZIPALIGN_BIN" && -x "$ZIPALIGN_BIN" ]] || {
    echo "ERR: zipalign unavailable; pass --zipalign or set ANDROID_HOME" >&2; exit 1;
}

APKSIGNER_COMMAND=()
if [[ -z "$APKSIGNER_PATH" ]]; then
    APKSIGNER_PATH="$(command -v apksigner || find_sdk_tool apksigner || true)"
fi
if [[ "$APKSIGNER_PATH" == *.jar ]]; then
    command -v java &>/dev/null || { echo "ERR: Java unavailable for apksigner JAR" >&2; exit 1; }
    APKSIGNER_COMMAND=("$(command -v java)" "-jar" "$APKSIGNER_PATH")
elif [[ -n "$APKSIGNER_PATH" && -x "$APKSIGNER_PATH" ]]; then
    APKSIGNER_COMMAND=("$APKSIGNER_PATH")
else
    echo "ERR: apksigner unavailable; pass --apksigner or set APKSIGNER_JAR" >&2; exit 1
fi

[[ -n "$KEYSTORE" && -f "$KEYSTORE" ]] || {
    echo "ERR: existing analysis keystore required; pass --keystore" >&2; exit 1;
}

OUT_DIR="${OUT_DIR:-$(dirname "$PROJECT_DIR")}"
BASE_NAME="${BASE_NAME:-$(basename "$PROJECT_DIR")}"

# Reject path-escape and trivially unsafe output names before any deletion or creation.
case "$BASE_NAME" in
    ""|"."|".."|*/*|*\\*)
        echo "ERR: --name must be a plain name without path separators or traversal: $BASE_NAME" >&2
        exit 2 ;;
esac
OUT_DIR_CANONICAL="$(mkdir -p "$OUT_DIR" && cd "$OUT_DIR" && pwd -P)" || {
    echo "ERR: output directory is not accessible: $OUT_DIR" >&2
    exit 1
}
OUT_DIR="$OUT_DIR_CANONICAL"
mkdir -p "$OUT_DIR"
UNSIGNED_APK="$OUT_DIR/${BASE_NAME}-unsigned.apk"
ALIGNED_APK="$OUT_DIR/${BASE_NAME}-aligned.apk"
SIGNED_APK="$OUT_DIR/${BASE_NAME}-signed.apk"
[[ "$CLEAN" == "false" ]] || rm -f "$UNSIGNED_APK" "$ALIGNED_APK" "$SIGNED_APK"

apktool b "$PROJECT_DIR" -o "$UNSIGNED_APK"
"$ZIPALIGN_BIN" -f -p 4 "$UNSIGNED_APK" "$ALIGNED_APK"
"$ZIPALIGN_BIN" -c -p 4 "$ALIGNED_APK"
"${APKSIGNER_COMMAND[@]}" sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" \
    --ks-pass "pass:$STORE_PASS" --key-pass "pass:$KEY_PASS" \
    --out "$SIGNED_APK" "$ALIGNED_APK"
"${APKSIGNER_COMMAND[@]}" verify --verbose --print-certs "$SIGNED_APK"
printf 'signed_apk=%s\nsha256=%s\n' "$SIGNED_APK" "$(sha256sum "$SIGNED_APK" | cut -d' ' -f1)"

if [[ "$DO_INSTALL" == "true" ]]; then
    adb_args=()
    [[ -z "$DEVICE_SERIAL" ]] || adb_args+=("-s" "$DEVICE_SERIAL")
    adb_args+=("install")
    [[ "$REINSTALL" == "false" ]] || adb_args+=("-r")
    adb_args+=("$SIGNED_APK")
    set +e
    install_output="$(adb "${adb_args[@]}" 2>&1)"
    install_exit=$?
    set -e
    printf '%s\n' "$install_output"
    if [[ "$install_exit" -ne 0 ]]; then
        [[ "$install_output" != *"INSTALL_FAILED_UPDATE_INCOMPATIBLE"* ]] || \
            echo "ERR: signer mismatch; never silently uninstall the store build" >&2
        [[ "$install_output" != *"INSTALL_FAILED_MISSING_SPLIT"* ]] || \
            echo "ERR: target requires a complete compatible split set" >&2
        exit "$install_exit"
    fi
fi
