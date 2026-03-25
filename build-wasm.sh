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

echo "Building default Caliptra ROM/FW assets..."
cargo run --quiet --manifest-path "$SCRIPT_DIR/tools/Cargo.toml" --bin build-default-assets -- "$SCRIPT_DIR/www"

echo ""
echo "Build complete! To run:"
echo "  cd $SCRIPT_DIR/www"
echo "  python3 -m http.server 8080"
echo "  Then open http://localhost:8080"
