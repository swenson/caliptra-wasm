#!/bin/bash
# Build the Caliptra WASM emulator and set up the www/ directory for serving.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check for wasm-pack
if ! command -v wasm-pack &>/dev/null; then
    echo "wasm-pack not found. Installing..."
    cargo install wasm-pack --locked
fi

# Check for wasm32 target
if ! rustup target list --installed | grep -q wasm32-unknown-unknown; then
    echo "Adding wasm32-unknown-unknown target..."
    rustup target add wasm32-unknown-unknown
fi

# Check for riscv target used by caliptra-builder
if ! rustup target list --installed | grep -q riscv32imc-unknown-none-elf; then
    echo "Adding riscv32imc-unknown-none-elf target..."
    rustup target add riscv32imc-unknown-none-elf
fi

echo "Building WASM (release)..."
wasm-pack build --target web --release

echo "Copying WASM output to www/..."
cp pkg/caliptra_wasm_demo_bg.wasm www/
cp pkg/caliptra_wasm_demo.js www/

# Generate error code lookup table for the UI's fatal error decoder
echo "Generating www/error-codes.json..."
./tools/build-error-codes.py || echo "(warning: error-codes.json generation failed)"

# Upstream revisions pinned in Cargo.toml. These are the single source of
# truth: the MCU ROM/runtime must be built from exactly the caliptra-mcu-sw
# rev the emulator is compiled from, or the MCU ROM may not run on the
# emulated hardware (e.g. a newer ROM fails with ROM_OTP_INIT_NOT_IDLE).
pinned_rev() {
    grep -oE "github.com/[^\"]+/$1\", rev = \"[0-9a-f]+\"" Cargo.toml | head -1 | sed -E 's/.*rev = "([0-9a-f]+)"/\1/'
}
pinned_url() {
    grep -oE "https://github.com/[^\"]+/$1\"" Cargo.toml | head -1 | tr -d '"'
}
export CALIPTRA_SW_REV="$(pinned_rev caliptra-sw)"
export CALIPTRA_MCU_SW_REV="$(pinned_rev caliptra-mcu-sw)"
MCU_SW_URL="$(pinned_url caliptra-mcu-sw)"
if [ -z "$CALIPTRA_MCU_SW_REV" ] || [ -z "$MCU_SW_URL" ]; then
    echo "ERROR: could not find the caliptra-mcu-sw git rev in Cargo.toml" >&2
    exit 1
fi

# Locate the caliptra-mcu-sw checkout used to build the MCU ROM/runtime.
#
# By default build-wasm.sh keeps its own checkout in a cache directory and
# moves it to the pinned rev on every build, so it never picks up whatever a
# developer's own caliptra-mcu-sw clone happens to have checked out. The cache
# must live outside this repository: caliptra-mcu-sw's build would otherwise
# find caliptra-wasm's Cargo.toml above it.
#
# Set MCU_SW_DIR to build from an existing checkout instead (e.g. while
# developing the fork). It must be at the pinned rev unless
# ALLOW_MCU_SW_MISMATCH=1.
if [ -n "${MCU_SW_DIR:-}" ]; then
    MCU_SW_DIR="$(cd "$MCU_SW_DIR" && pwd)"
    MCU_HEAD="$(git -C "$MCU_SW_DIR" rev-parse HEAD)"
    if [ "$MCU_HEAD" != "$CALIPTRA_MCU_SW_REV" ]; then
        if [ "${ALLOW_MCU_SW_MISMATCH:-0}" = "1" ]; then
            echo "WARNING: building MCU ROM/runtime from $MCU_SW_DIR at $MCU_HEAD," >&2
            echo "  but Cargo.toml pins caliptra-mcu-sw $CALIPTRA_MCU_SW_REV (ALLOW_MCU_SW_MISMATCH=1)." >&2
            CALIPTRA_MCU_SW_REV="$MCU_HEAD"
        else
            echo "ERROR: MCU_SW_DIR=$MCU_SW_DIR is at $MCU_HEAD," >&2
            echo "  but Cargo.toml pins caliptra-mcu-sw $CALIPTRA_MCU_SW_REV." >&2
            echo "  Check out the pinned rev, unset MCU_SW_DIR to use the build cache," >&2
            echo "  or set ALLOW_MCU_SW_MISMATCH=1 to build anyway." >&2
            exit 1
        fi
    fi
    if [ -n "$(git -C "$MCU_SW_DIR" status --porcelain --untracked-files=no)" ]; then
        echo "WARNING: $MCU_SW_DIR has uncommitted changes; the MCU ROM/runtime may not match $CALIPTRA_MCU_SW_REV" >&2
    fi
else
    MCU_SW_DIR="${MCU_SW_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/caliptra-wasm/caliptra-mcu-sw}"
    case "$MCU_SW_DIR/" in
        "$SCRIPT_DIR"/*)
            echo "ERROR: MCU_SW_CACHE_DIR must be outside $SCRIPT_DIR" >&2
            exit 1
            ;;
    esac
    if [ ! -d "$MCU_SW_DIR/.git" ]; then
        echo "Cloning $MCU_SW_URL into $MCU_SW_DIR..."
        mkdir -p "$(dirname "$MCU_SW_DIR")"
        git clone --filter=blob:none --no-checkout "$MCU_SW_URL" "$MCU_SW_DIR"
    fi
    if ! git -C "$MCU_SW_DIR" cat-file -e "$CALIPTRA_MCU_SW_REV^{commit}" 2>/dev/null; then
        echo "Fetching caliptra-mcu-sw $CALIPTRA_MCU_SW_REV..."
        git -C "$MCU_SW_DIR" fetch --filter=blob:none origin "$CALIPTRA_MCU_SW_REV"
    fi
    git -C "$MCU_SW_DIR" checkout --quiet --force --detach "$CALIPTRA_MCU_SW_REV"
fi
echo "Using caliptra-mcu-sw $CALIPTRA_MCU_SW_REV at $MCU_SW_DIR"

# Print the most recently modified of the given files that exist. The MCU
# build output names/profiles have changed across caliptra-mcu-sw releases
# (e.g. release/mcu-rom-emulator.bin -> release/caliptra-mcu-rom-emulator.bin,
# release/runtime-emulator.bin -> devel/runtime-emulator.bin), so try them all
# and take the freshest so a stale artifact from an older build never wins.
newest_existing() {
    local f existing=()
    for f in "$@"; do
        [ -f "$f" ] && existing+=("$f")
    done
    [ ${#existing[@]} -gt 0 ] && ls -t "${existing[@]}" | head -1
    return 0
}

MCU_TARGET="$MCU_SW_DIR/target/riscv32imc-unknown-none-elf"

echo "Building MCU ROM from $MCU_SW_DIR..."
(cd "$MCU_SW_DIR" && cargo xtask rom-build 2>&1 | tail -3)
MCU_ROM="$(newest_existing "$MCU_TARGET/release/caliptra-mcu-rom-emulator.bin" "$MCU_TARGET/release/mcu-rom-emulator.bin")"
if [ -z "$MCU_ROM" ]; then
    echo "ERROR: MCU ROM not found under $MCU_TARGET/release" >&2
    exit 1
fi
cp "$MCU_ROM" "$SCRIPT_DIR/www/default-mcu-rom.bin"
echo "Copied MCU ROM ($(wc -c < "$MCU_ROM") bytes) to www/default-mcu-rom.bin"

echo "Building MCU runtime from $MCU_SW_DIR..."
(cd "$MCU_SW_DIR" && cargo xtask runtime-build 2>&1 | tail -3)
# `cargo xtask runtime-build` emits runtime-<platform>.bin (emulator by
# default), not runtime.bin. The name must match exactly: build-default-assets
# hashes this file into the SoC manifest, so a wrong/missing path silently
# falls back to DEFAULT_MCU_FW and the served runtime fails to validate (b0016).
MCU_RUNTIME="$(newest_existing "$MCU_TARGET/devel/runtime-emulator.bin" "$MCU_TARGET/release/runtime-emulator.bin")"
if [ -z "$MCU_RUNTIME" ]; then
    echo "ERROR: MCU runtime not found under $MCU_TARGET (devel/ or release/runtime-emulator.bin)" >&2
    exit 1
fi
cp "$MCU_RUNTIME" "$SCRIPT_DIR/www/default-mcu-runtime.bin"
echo "Copied MCU runtime ($(wc -c < "$MCU_RUNTIME") bytes) to www/default-mcu-runtime.bin"

echo "Building default Caliptra ROM/FW assets..."
cargo run --quiet --manifest-path "$SCRIPT_DIR/tools/Cargo.toml" --bin build-default-assets -- "$SCRIPT_DIR/www" "$MCU_RUNTIME"

echo ""
echo "Build complete! To run:"
echo "  cd $SCRIPT_DIR/www"
echo "  python3 -m http.server 8080"
echo "  Then open http://localhost:8080"
