#!/bin/bash
# Licensed under the Apache-2.0 license
#
# Build the Caliptra WASM emulator for each Caliptra release and set up www/.
#
# Each release has a build directory under versions/<release>/ (its own
# Cargo.toml, lockfile and toolchain; the crate source in src/ is shared).
# For every release this script:
#   * builds the WASM module into www/v<release>/,
#   * for 2.x, builds that release's MCU ROM and runtime from caliptra-mcu-sw
#     at the rev pinned in versions/<release>/Cargo.toml and generates the
#     default Caliptra ROM/FW, a matching SoC manifest and defaults.json;
#   * for 1.x (a release directory with a firmware.json), downloads and
#     verifies the official ROM and firmware releases it lists instead, since
#     1.x is core-only and its firmware does not need building;
#   * writes build-info.json, error-codes.json and mailbox-commands.json into
#     www/v<release>/,
# then builds the test CA (ca/, the same for every release) into www/ca/, and
# finally writes www/versions.json, which the page reads to offer the
# releases that were built.
#
# Environment:
#   CALIPTRA_VERSIONS   Space-separated releases to build (default: all of
#                       versions/*). Releases already in www/ stay listed.
#   MCU_SW_DIR_<rel>    Build that release's MCU firmware from an existing
#                       caliptra-mcu-sw checkout instead of the build cache,
#                       e.g. MCU_SW_DIR_2_1=~/src/caliptra-mcu-sw. It must be
#                       at the pinned rev unless ALLOW_MCU_SW_MISMATCH=1.
#                       MCU_SW_DIR is accepted when building one release.
#   MCU_SW_CACHE_DIR    Parent directory for the build cache's checkouts
#                       (default: ~/.cache/caliptra-wasm). Must be outside
#                       this repository.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

sort_releases() { tr ' ' '\n' | grep -v '^$' | sort -t. -k1,1nr -k2,2nr; }

ALL_RELEASES="$(ls -d versions/*/ | xargs -n1 basename | sort_releases | tr '\n' ' ')"
RELEASES="$(echo "${CALIPTRA_VERSIONS:-$ALL_RELEASES}" | sort_releases | tr '\n' ' ')"
for rel in $RELEASES; do
    if [ ! -f "versions/$rel/Cargo.toml" ]; then
        echo "ERROR: no build directory versions/$rel (have: $ALL_RELEASES)" >&2
        exit 1
    fi
done
NUM_RELEASES=$(echo $RELEASES | wc -w)
if [ -n "${MCU_SW_DIR:-}" ] && [ "$NUM_RELEASES" -ne 1 ]; then
    echo "ERROR: MCU_SW_DIR applies to one release; set CALIPTRA_VERSIONS or use MCU_SW_DIR_<release>" >&2
    exit 1
fi
echo "Building Caliptra releases: $RELEASES"

if ! command -v wasm-pack &>/dev/null; then
    echo "wasm-pack not found. Installing..."
    cargo install wasm-pack --locked
fi

CACHE_ROOT="${MCU_SW_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/caliptra-wasm}"
case "$CACHE_ROOT/" in
    "$SCRIPT_DIR"/*)
        echo "ERROR: MCU_SW_CACHE_DIR must be outside $SCRIPT_DIR" >&2
        exit 1
        ;;
esac

# Print the git rev / URL that a manifest pins for the given repository name.
pinned_rev() {
    grep -oE "github.com/[^\"]+/$2\", rev = \"[0-9a-f]+\"" "$1" | head -1 | sed -E 's/.*rev = "([0-9a-f]+)"/\1/'
}
pinned_url() {
    grep -oE "https://github.com/[^\"]+/$2\"" "$1" | head -1 | tr -d '"'
}

# Print the most recently modified of the given files that exist. The MCU
# build output names/profiles differ across caliptra-mcu-sw releases
# (release/mcu-rom-emulator.bin vs release/caliptra-mcu-rom-emulator.bin,
# release/ vs devel/ runtime), so try them all and take the freshest.
newest_existing() {
    local f existing=()
    for f in "$@"; do
        [ -f "$f" ] && existing+=("$f")
    done
    [ ${#existing[@]} -gt 0 ] && ls -t "${existing[@]}" | head -1
    return 0
}

# Print the root of the cargo checkout that provides a package, as resolved
# for the release in directory $1.
package_root() {
    (cd "$1" && cargo metadata --format-version 1 --quiet) | python3 -c '
import json, os, sys
name, up = sys.argv[1], int(sys.argv[2])
for p in json.load(sys.stdin)["packages"]:
    if p["name"] == name:
        d = os.path.dirname(p["manifest_path"])
        for _ in range(up):
            d = os.path.dirname(d)
        print(d)
        break
' "$2" "$3"
}

# Check out caliptra-mcu-sw at the pinned rev and print its directory.
mcu_checkout() {
    local rel="$1" url="$2" rev="$3" var dir head
    var="MCU_SW_DIR_${rel//./_}"
    dir="${!var:-${MCU_SW_DIR:-}}"
    if [ -n "$dir" ]; then
        dir="$(cd "$dir" && pwd)"
        head="$(git -C "$dir" rev-parse HEAD)"
        if [ "$head" != "$rev" ]; then
            if [ "${ALLOW_MCU_SW_MISMATCH:-0}" = "1" ]; then
                echo "WARNING: $dir is at $head, but versions/$rel pins $rev (ALLOW_MCU_SW_MISMATCH=1)" >&2
            else
                echo "ERROR: $dir is at $head, but versions/$rel/Cargo.toml pins caliptra-mcu-sw $rev." >&2
                echo "  Check out the pinned rev, unset $var to use the build cache," >&2
                echo "  or set ALLOW_MCU_SW_MISMATCH=1 to build anyway." >&2
                return 1
            fi
        fi
        if [ -n "$(git -C "$dir" status --porcelain --untracked-files=no)" ]; then
            echo "WARNING: $dir has uncommitted changes; the MCU firmware may not match $rev" >&2
        fi
    else
        dir="$CACHE_ROOT/caliptra-mcu-sw-$rel"
        if [ ! -d "$dir/.git" ]; then
            echo "Cloning $url into $dir..." >&2
            mkdir -p "$CACHE_ROOT"
            git clone --quiet --filter=blob:none --no-checkout "$url" "$dir" >&2
        fi
        if ! git -C "$dir" cat-file -e "$rev^{commit}" 2>/dev/null; then
            echo "Fetching caliptra-mcu-sw $rev..." >&2
            git -C "$dir" fetch --quiet --filter=blob:none origin "$rev" >&2
        fi
        git -C "$dir" checkout --quiet --force --detach "$rev" >&2
    fi
    echo "$dir"
}

build_release() {
    local rel="$1"
    local dir="versions/$rel" out="www/v$rel"
    local manifest="$dir/Cargo.toml"
    echo ""
    echo "=== Caliptra $rel ==="
    mkdir -p "$out"

    # Toolchains (and their wasm32/riscv32 targets) come from the
    # rust-toolchain.toml files in the release directory.
    (cd "$dir" && rustup toolchain install >/dev/null)
    if [ -f "$dir/tools/rust-toolchain.toml" ]; then
        (cd "$dir/tools" && rustup toolchain install >/dev/null)
    fi

    echo "Building WASM..."
    (cd "$dir" && wasm-pack build --target web --release)
    cp "$dir/pkg/caliptra_wasm_demo_bg.wasm" "$dir/pkg/caliptra_wasm_demo.js" "$out/"

    local caliptra_sw_rev caliptra_sw_url caliptra_sw_src
    caliptra_sw_rev="$(pinned_rev "$manifest" caliptra-sw)"
    caliptra_sw_url="$(pinned_url "$manifest" caliptra-sw)"
    if [ -z "$caliptra_sw_rev" ]; then
        echo "ERROR: could not find the caliptra-sw rev in $manifest" >&2
        return 1
    fi
    caliptra_sw_src="$(package_root "$dir" caliptra-api 1)"
    ./tools/build-mailbox-commands.py --caliptra-sw "$caliptra_sw_src" -o "$out/mailbox-commands.json"

    if [ -f "$dir/firmware.json" ]; then
        # 1.x: core only, so no MCU; the ROM and firmware are the official
        # releases, downloaded and checked against firmware.json's hashes.
        ./tools/build-error-codes.py --manifest "$manifest" \
            --caliptra-sw "$caliptra_sw_src/error/src/lib.rs" --mcu-sw none \
            -o "$out/error-codes.json"
        ./tools/fetch-firmware.py "$dir/firmware.json" "$out" --cache "$CACHE_ROOT/releases"
        python3 - "$rel" "$caliptra_sw_rev" "$caliptra_sw_url" "$out" <<'PYEOF'
import json, os, sys
rel, rev, repo, out = sys.argv[1:]
fw = json.load(open(os.path.join(out, "firmware.json")))
info = {
    "caliptra_release": rel,
    "hardware": rel,
    "caliptra_sw_rev": rev,
    "caliptra_mcu_sw_rev": "",
    "caliptra_sw_repo": repo,
    "caliptra_mcu_sw_repo": "",
    "default_rom": fw["default_rom"],
    "default_firmware": fw["default_firmware"],
    "features": {"ocp_lock": False, "subsystem": False, "release_firmware": True},
}
with open(os.path.join(out, "build-info.json"), "w") as f:
    json.dump(info, f, indent=2)
    f.write("\n")
print(f"Wrote {out}/build-info.json")
PYEOF
        return
    fi

    local mcu_rev mcu_url
    mcu_rev="$(pinned_rev "$manifest" caliptra-mcu-sw)"
    mcu_url="$(pinned_url "$manifest" caliptra-mcu-sw)"
    if [ -z "$mcu_rev" ] || [ -z "$mcu_url" ]; then
        echo "ERROR: could not find the caliptra-mcu-sw rev in $manifest" >&2
        return 1
    fi

    # Firmware error codes, from the exact caliptra-sw / caliptra-mcu-sw
    # sources this release uses.
    local mcu_sw_src
    mcu_sw_src="$(package_root "$dir" caliptra-mcu-hw-model 2)"
    ./tools/build-error-codes.py --manifest "$manifest" \
        --caliptra-sw "$caliptra_sw_src/error/src/lib.rs" \
        --mcu-sw "$mcu_sw_src/error/src/lib.rs" \
        -o "$out/error-codes.json"

    # MCU ROM and runtime. They must come from the same caliptra-mcu-sw rev as
    # the emulator: an MCU ROM from another rev may not run on it (e.g. one
    # from upstream main stops with ROM_OTP_INIT_NOT_IDLE). The checkout must
    # be outside this repository, or its build finds our versions/ manifests.
    local mcu_dir mcu_target mcu_rom mcu_runtime
    mcu_dir="$(mcu_checkout "$rel" "$mcu_url" "$mcu_rev")"
    echo "Using caliptra-mcu-sw $mcu_rev at $mcu_dir"
    mcu_target="$mcu_dir/target/riscv32imc-unknown-none-elf"

    echo "Building MCU ROM..."
    (cd "$mcu_dir" && cargo xtask rom-build 2>&1 | tail -3)
    mcu_rom="$(newest_existing "$mcu_target/release/caliptra-mcu-rom-emulator.bin" "$mcu_target/release/mcu-rom-emulator.bin")"
    if [ -z "$mcu_rom" ]; then
        echo "ERROR: MCU ROM not found under $mcu_target/release" >&2
        return 1
    fi
    cp "$mcu_rom" "$out/default-mcu-rom.bin"
    echo "Copied MCU ROM ($(wc -c < "$mcu_rom") bytes)"

    # The runtime's user app reads its SoC image load list from
    # target/generated/. 2.1's runtime build writes it; 2.0's expects it to
    # exist already, and without it falls back to two test SoC images (fw_id
    # 4096 and 4097) that the default SoC manifest does not authorize, so the
    # app exits at boot. Write the config upstream's builder generates when
    # there are no SoC images, as `cargo xtask runtime` does.
    local generated="$mcu_dir/target/generated"
    if [ ! -f "$generated/soc_image_descriptors.toml" ]; then
        mkdir -p "$generated"
        printf '%s\n' "# Licensed under the Apache-2.0 license" "# AUTO-GENERATED FILE. DO NOT EDIT." \
            "# Generated by caliptra-wasm build-wasm.sh (no SoC images)" \
            'vendor = "ChipsAlliance"' 'model = "Caliptra-SS"' 'components = []' \
            > "$generated/attestation_manifest.toml"
        printf '%s\n' "# Licensed under the Apache-2.0 license" "# AUTO-GENERATED FILE. DO NOT EDIT." \
            "# Generated by caliptra-wasm build-wasm.sh (no SoC images)" 'images = []' \
            > "$generated/soc_image_descriptors.toml"
    fi

    echo "Building MCU runtime..."
    (cd "$mcu_dir" && cargo xtask runtime-build 2>&1 | tail -3)
    # The asset tool hashes this exact file into the SoC manifest, so the
    # served runtime must be the one found here.
    mcu_runtime="$(newest_existing "$mcu_target/devel/runtime-emulator.bin" "$mcu_target/release/runtime-emulator.bin")"
    if [ -z "$mcu_runtime" ]; then
        echo "ERROR: MCU runtime not found under $mcu_target (devel/ or release/runtime-emulator.bin)" >&2
        return 1
    fi
    cp "$mcu_runtime" "$out/default-mcu-runtime.bin"
    echo "Copied MCU runtime ($(wc -c < "$mcu_runtime") bytes)"

    echo "Building default Caliptra ROM/FW assets..."
    (cd "$dir/tools" && CALIPTRA_SW_REV="$caliptra_sw_rev" CALIPTRA_MCU_SW_REV="$mcu_rev" \
        CALIPTRA_SW_REPO="$caliptra_sw_url" CALIPTRA_MCU_SW_REPO="$mcu_url" \
        cargo run --quiet --bin build-default-assets -- "$SCRIPT_DIR/$out" "$mcu_runtime")
}

for rel in $RELEASES; do
    build_release "$rel"
done

# The test CA behind the Test CA page and the Provisioning section, which also
# does the hashing and P-384 signing for the two calculator pages. It does not
# depend on the Caliptra release, so there is one build for the whole site.
echo ""
echo "=== Test CA ==="
(cd ca && rustup toolchain install >/dev/null)
(cd ca && wasm-pack build --target web --release)
mkdir -p www/ca
cp ca/pkg/caliptra_test_ca_bg.wasm ca/pkg/caliptra_test_ca.js www/ca/

# List every release present in www/ (newest first; the newest is the default).
python3 - <<'EOF'
import json, os
releases = sorted(
    (d[1:] for d in os.listdir("www")
     if d.startswith("v") and os.path.exists(os.path.join("www", d, "build-info.json"))),
    key=lambda v: [int(x) for x in v.split(".")], reverse=True)
with open("www/versions.json", "w") as f:
    json.dump({"default": releases[0], "releases": releases}, f, indent=1)
    f.write("\n")
print(f"Wrote www/versions.json: {', '.join(releases)} (default {releases[0]})")
EOF

echo ""
echo "Build complete! To run:"
echo "  cd $SCRIPT_DIR/www"
echo "  python3 -m http.server 8080"
echo "  Then open http://localhost:8080"
