#!/bin/bash
# Licensed under the Apache-2.0 license
#
# fmt + clippy for every Caliptra release build in versions/. The sources in
# src/ and tools/src/ are shared, so each release's build checks the code
# paths its `caliptra-2-*` feature selects.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

for dir in versions/*/; do
    rel="$(basename "$dir")"
    echo "=== Caliptra $rel ==="

    echo "Running cargo fmt --check..."
    (cd "$dir" && cargo fmt --all --check)
    (cd "$dir/tools" && cargo fmt --all --check)

    echo "Running cargo clippy (host, all targets)..."
    (cd "$dir" && cargo clippy --all-targets -- -D warnings)

    echo "Running cargo clippy (wasm32)..."
    (cd "$dir" && cargo clippy --target wasm32-unknown-unknown -- -D warnings)

    echo "Running cargo clippy (tools)..."
    (cd "$dir/tools" && cargo clippy --all-targets -- -D warnings)
done

echo "Precheckin passed."
