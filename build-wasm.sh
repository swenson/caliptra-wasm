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

# Build MCU ROM and runtime from caliptra-mcu-sw (must happen before asset generation)
MCU_SW_DIR="${MCU_SW_DIR:-}"
if [ -z "$MCU_SW_DIR" ]; then
    # Try common locations
    for d in "../caliptra-mcu-sw" "../mcu-sw"; do
        if [ -f "$d/Cargo.toml" ] && grep -q 'mcu-hw-model' "$d/Cargo.toml" 2>/dev/null; then
            MCU_SW_DIR="$(cd "$d" && pwd)"
            break
        fi
    done
fi

MCU_RUNTIME_PATH=""
if [ -n "$MCU_SW_DIR" ]; then
    echo "Building MCU ROM from $MCU_SW_DIR..."
    (cd "$MCU_SW_DIR" && cargo xtask rom-build 2>&1 | tail -3)
    MCU_ROM="$MCU_SW_DIR/target/riscv32imc-unknown-none-elf/release/mcu-rom-emulator.bin"
    if [ -f "$MCU_ROM" ]; then
        cp "$MCU_ROM" "$SCRIPT_DIR/www/default-mcu-rom.bin"
        echo "Copied MCU ROM ($(wc -c < "$MCU_ROM") bytes) to www/default-mcu-rom.bin"
    else
        echo "WARNING: MCU ROM not found at $MCU_ROM"
    fi

    echo "Building MCU runtime from $MCU_SW_DIR..."
    (cd "$MCU_SW_DIR" && cargo xtask runtime-build --features test-spdm-validator 2>&1 | tail -3)
    MCU_RUNTIME="$MCU_SW_DIR/target/riscv32imc-unknown-none-elf/release/runtime.bin"
    if [ -f "$MCU_RUNTIME" ]; then
        cp "$MCU_RUNTIME" "$SCRIPT_DIR/www/default-mcu-runtime.bin"
        echo "Copied MCU runtime ($(wc -c < "$MCU_RUNTIME") bytes) to www/default-mcu-runtime.bin"
        MCU_RUNTIME_PATH="$MCU_RUNTIME"
    else
        echo "WARNING: MCU runtime not found at $MCU_RUNTIME"
    fi
else
    echo "WARNING: caliptra-mcu-sw not found. Set MCU_SW_DIR or place it at ../caliptra-mcu-sw"
    echo "  MCU emulator will require manual ROM/runtime upload."
fi

echo "Building default Caliptra ROM/FW assets..."
if [ -n "$MCU_RUNTIME_PATH" ]; then
    cargo run --quiet --manifest-path "$SCRIPT_DIR/tools/Cargo.toml" --bin build-default-assets -- "$SCRIPT_DIR/www" "$MCU_RUNTIME_PATH"
else
    cargo run --quiet --manifest-path "$SCRIPT_DIR/tools/Cargo.toml" --bin build-default-assets -- "$SCRIPT_DIR/www"
fi

echo ""
echo "Build complete! To run:"
echo "  cd $SCRIPT_DIR/www"
echo "  python3 -m http.server 8080"
echo "  Then open http://localhost:8080"
