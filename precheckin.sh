#!/bin/bash
# Licensed under the Apache-2.0 license
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Running cargo fmt --check (root)..."
cargo fmt --all --check

echo "Running cargo clippy (root)..."
cargo clippy --all-targets -- -D warnings

echo "Running cargo fmt --check (tools)..."
cargo fmt --manifest-path tools/Cargo.toml --check

echo "Running cargo clippy (tools)..."
cargo clippy --manifest-path tools/Cargo.toml --all-targets -- -D warnings

echo "Precheckin passed."
