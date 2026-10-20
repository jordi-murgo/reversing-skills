#!/usr/bin/env bash
# jadx + apktool decode with isolated per-DEX fallback.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: decode.sh APK [--name NAME] [--out DIR] [--per-dex]
                     [--skip-jadx] [--skip-apktool] [--clean]

Full-APK jadx is attempted first unless --per-dex is set. On failure, every
classes*.dex is decompiled into its own directory. Trees are never merged.
EOF
}

need_value() {
    [[ $# -ge 2 && -n "$2" ]] || { echo "ERR: $1 requires a value" >&2; exit 2; }
}

ensure_tool() {
    local name="$1"
    command -v "$name" &>/dev/null || {
        echo "ERR: required tool unavailable: $name" >&2
        return 1
    }
}

APK_PATH=""
TASK_NAME=""
OUT_ROOT=""
SKIP_JADX=false
SKIP_APKTOOL=false
FORCE_PER_DEX=false
CLEAN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name) need_value "$@"; TASK_NAME="$2"; shift 2 ;;
        --out) need_value "$@"; OUT_ROOT="$2"; shift 2 ;;
        --per-dex) FORCE_PER_DEX=true; shift ;;
        --skip-jadx) SKIP_JADX=true; shift ;;
        --skip-apktool) SKIP_APKTOOL=true; shift ;;
        --clean) CLEAN=true; shift ;;
        --help|-h) usage; exit 0 ;;
        -*) echo "ERR: unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) [[ -z "$APK_PATH" ]] || { echo "ERR: multiple APK paths supplied" >&2; exit 2; }
           APK_PATH="$1"; shift ;;
    esac
done

[[ -n "$APK_PATH" ]] || { usage >&2; exit 2; }
[[ -f "$APK_PATH" ]] || { echo "ERR: APK not found: $APK_PATH" >&2; exit 1; }

if [[ -n "${JADX:-}" ]]; then
    [[ -x "$JADX" ]] || { echo "ERR: JADX is not executable: $JADX" >&2; exit 1; }
    PATH="$(dirname "$JADX"):$PATH"
fi
[[ "$SKIP_JADX" == "true" ]] || ensure_tool jadx
[[ "$SKIP_APKTOOL" == "true" ]] || ensure_tool apktool

APK_BASENAME="$(basename "$APK_PATH" .apk | sed 's/[^A-Za-z0-9._-]/_/g')"
TASK_NAME="${TASK_NAME:-$APK_BASENAME}"
OUT_ROOT="${OUT_ROOT:-$(dirname "$APK_PATH")}"

# Reject path-escape and trivially unsafe task names before any deletion or creation.
case "$TASK_NAME" in
    ""|"."|".."|*/*|*\\*)
        echo "ERR: --name must be a plain name without path separators or traversal: $TASK_NAME" >&2
        exit 2 ;;
esac
OUT_ROOT_CANONICAL="$(mkdir -p "$OUT_ROOT" && cd "$OUT_ROOT" && pwd -P)" || {
    echo "ERR: output root is not an accessible directory: $OUT_ROOT" >&2
    exit 1
}
OUT_ROOT="$OUT_ROOT_CANONICAL"
TASK_ROOT="$OUT_ROOT/$TASK_NAME"
JADX_OUT="$TASK_ROOT/jadx"
JADX_DEX_OUT="$TASK_ROOT/jadx-dex"
JADX_PARTIAL_OUT="$TASK_ROOT/jadx-full-partial"
DEX_DIR="$TASK_ROOT/dex"
APKTOOL_OUT="$TASK_ROOT/apktool"

if [[ "$CLEAN" == "true" && -d "$TASK_ROOT" ]]; then
    rm -rf "$TASK_ROOT"
fi
mkdir -p "$TASK_ROOT"

JADX_MODE="skipped"
JADX_FULL_EXIT=0
JADX_DEX_EXIT=0
JADX_XMX="${JADX_XMX:-3500m}"
JADX_JOBS="${JADX_JOBS:-4}"

decompile_per_dex() {
    ensure_tool unzip
    rm -rf "$DEX_DIR" "$JADX_DEX_OUT"
    mkdir -p "$DEX_DIR" "$JADX_DEX_OUT"

    local entries=()
    mapfile -t entries < <(unzip -Z1 "$APK_PATH" | grep -E '^classes([0-9]+)?\.dex$' || true)
    [[ ${#entries[@]} -gt 0 ]] || {
        echo "ERR: no classes*.dex entries found in $APK_PATH" >&2
        return 1
    }

    local entry dex output dex_exit rc=0
    for entry in "${entries[@]}"; do
        dex="$DEX_DIR/$(basename "$entry")"
        output="$JADX_DEX_OUT/$(basename "${entry%.dex}")"
        unzip -p "$APK_PATH" "$entry" > "$dex"
        echo "=== jadx per DEX: $entry ==="
        if JAVA_OPTS="-Xmx$JADX_XMX" jadx --no-res --no-imports -j "$JADX_JOBS" \
            -d "$output" "$dex"; then
            :
        else
            dex_exit=$?
            echo "WARN: jadx exited $dex_exit for $entry; partial output retained" >&2
            rc="$dex_exit"
        fi
    done
    return "$rc"
}

if [[ "$SKIP_JADX" != "true" ]]; then
    rm -rf "$JADX_OUT" "$JADX_PARTIAL_OUT"
    if [[ "$FORCE_PER_DEX" == "true" ]]; then
        JADX_MODE="per-dex"
        decompile_per_dex || JADX_DEX_EXIT=$?
    else
        echo "=== jadx full APK ==="
        if JAVA_OPTS="-Xmx$JADX_XMX" jadx --no-res --no-imports -j "$JADX_JOBS" \
            -d "$JADX_OUT" "$APK_PATH"; then
            JADX_MODE="full"
        else
            JADX_FULL_EXIT=$?
            JADX_MODE="per-dex-fallback"
            [[ ! -d "$JADX_OUT" ]] || mv "$JADX_OUT" "$JADX_PARTIAL_OUT"
            echo "WARN: full-APK jadx exited $JADX_FULL_EXIT; falling back per DEX" >&2
            decompile_per_dex || JADX_DEX_EXIT=$?
        fi
    fi
fi

APKTOOL_EXIT=0
if [[ "$SKIP_APKTOOL" != "true" ]]; then
    rm -rf "$APKTOOL_OUT"
    echo "=== apktool decode ==="
    apktool d "$APK_PATH" -o "$APKTOOL_OUT" -f || APKTOOL_EXIT=$?
fi

PACKAGE=""
if [[ -f "$APKTOOL_OUT/AndroidManifest.xml" ]]; then
    PACKAGE="$(grep -oP 'package="[^"]*"' "$APKTOOL_OUT/AndroidManifest.xml" 2>/dev/null \
        | head -1 | sed 's/package="//;s/"//' || true)"
fi

JAVA_ROOT="$JADX_OUT"
[[ "$JADX_MODE" == per-dex* ]] && JAVA_ROOT="$JADX_DEX_OUT"
JAVA_COUNT=0
[[ -d "$JAVA_ROOT" ]] && JAVA_COUNT="$(find "$JAVA_ROOT" -name '*.java' | wc -l)"
SMALI_DIRS=0
[[ -d "$APKTOOL_OUT" ]] && SMALI_DIRS="$(find "$APKTOOL_OUT" -maxdepth 1 -type d -name 'smali*' | wc -l)"
SO_COUNT=0
[[ -d "$APKTOOL_OUT" ]] && SO_COUNT="$(find "$APKTOOL_OUT" -name '*.so' | wc -l)"

OVERALL_EXIT=0
if [[ "$JADX_DEX_EXIT" -ne 0 ]]; then
    OVERALL_EXIT="$JADX_DEX_EXIT"
elif [[ "$APKTOOL_EXIT" -ne 0 ]]; then
    OVERALL_EXIT="$APKTOOL_EXIT"
fi

cat <<EOF

task_root=$TASK_ROOT
jadx_mode=$JADX_MODE
jadx_out=$JAVA_ROOT
jadx_full_partial=$([[ -d "$JADX_PARTIAL_OUT" ]] && echo "$JADX_PARTIAL_OUT" || true)
apktool_out=$APKTOOL_OUT
package=$PACKAGE
jadx_full_exit_code=$JADX_FULL_EXIT
jadx_per_dex_exit_code=$JADX_DEX_EXIT
apktool_exit_code=$APKTOOL_EXIT
java_files=$JAVA_COUNT
smali_dirs=$SMALI_DIRS
so_files=$SO_COUNT
EOF

exit "$OVERALL_EXIT"
