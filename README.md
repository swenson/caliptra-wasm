# caliptra-wasm

Run the [Caliptra](https://github.com/chipsalliance/caliptra-sw) root of trust
emulator — and the [Caliptra subsystem MCU](https://github.com/chipsalliance/caliptra-mcu-sw)
emulator — in the browser via WebAssembly.

**Current release: Caliptra 2.1** (ROM 2.1.3, FMC/RT 2.1.4, MCU `main-2.1`).
The page header shows the exact release and upstream commits the deployed
build was made from.

The site has three pages:

- **Emulator** (`www/index.html`): boot Caliptra core alone, or Caliptra + MCU
  in subsystem mode, with UART output, fuse/OTP editing, a KeyVault viewer, an
  OTP DAI log, and a fatal-error decoder.
- **PK Hash Calculator** (`www/pk-hash.html`): compute vendor/owner PK hashes.
- **Debug Unlock Calculator** (`www/debug-unlock.html`).

## Upstream sources

The emulators are built from small forks that carry the patches needed for
wasm32 (optional host-only dependencies, no filesystem or `process::exit`,
in-memory flash, plus a few inspection hooks for the UI):

| Repo | Branch | Based on |
| --- | --- | --- |
| [swenson/caliptra-sw](https://github.com/swenson/caliptra-sw/tree/wasm-2.1) | `wasm-2.1` | `chipsalliance/caliptra-sw` `e5d1f27b` (the rev `main-2.1` of caliptra-mcu-sw pins) |
| [swenson/caliptra-mcu-sw](https://github.com/swenson/caliptra-mcu-sw/tree/wasm-2.1) | `wasm-2.1` | `chipsalliance/caliptra-mcu-sw` `main-2.1` |

Revisions are pinned in `Cargo.toml` (and `tools/Cargo.toml`); keep them in
sync. The caliptra-mcu-sw fork must itself depend on the same caliptra-sw
fork rev. The MCU ROM and runtime are built from the caliptra-mcu-sw rev
pinned in `Cargo.toml`: an MCU ROM from any other rev may not run on the
emulator built here (for example, one from upstream `main` stops with
`ROM_OTP_INIT_NOT_IDLE`).

## Building

Requirements: rustup (the toolchain is pinned in `rust-toolchain.toml`),
[wasm-pack](https://rustwasm.github.io/wasm-pack/), Python 3, and git.

```sh
./build-wasm.sh
cd www && python3 -m http.server 8080
```

`build-wasm.sh` builds the WASM module, the MCU ROM and runtime, the default
Caliptra ROM/FW images, a matching SoC manifest, `error-codes.json`, and
`build-info.json`.

To build the MCU ROM/runtime, `build-wasm.sh` keeps its own clone of the
caliptra-mcu-sw fork in `~/.cache/caliptra-wasm/caliptra-mcu-sw` (override
with `MCU_SW_CACHE_DIR`). It checks out the pinned rev there on every build.
To build from your own checkout instead (e.g. while working on the fork), set
`MCU_SW_DIR=/path/to/caliptra-mcu-sw`. The build fails if that checkout is
not at the pinned rev, unless you also set `ALLOW_MCU_SW_MISMATCH=1`.

## Testing

Run `./precheckin.sh` (fmt + clippy) before sending changes. After
`./build-wasm.sh`:

```sh
# Native: boot both emulators from the www/ default assets.
cargo test --release

# Browser: serve www/, open the page in headless Firefox, press Run in each
# mode, and wait for the boot milestones (Caliptra RT ready; in subsystem
# mode also the MCU runtime main loop) with no fatal errors. Needs Node 22+
# and Firefox; no npm packages.
node tests/browser/boot-test.mjs            # or --mode mcu / --mode caliptra
```

CI runs the browser test on every pull request and before each deploy.

## TODO

- [ ] **Selectable Caliptra versions.** Let the user pick which Caliptra
  release to emulate: 1.0, 1.1, 1.2, 1.3 (core only) and 2.0, 2.1, 2.2
  (core + subsystem/MCU). The emulator page already has a (disabled)
  version selector and reads the active release from `build-info.json`.
  Rough plan:
  - Build one WASM module + default asset set per release, each from its own
    pinned caliptra-sw (and, for 2.x, caliptra-mcu-sw) fork branch, and
    publish them under per-version directories (e.g. `www/v2.1/`).
  - The hw-model / emulator APIs differ between releases (1.x has no
    subsystem mode or MCU; `InitParams` and fuse layouts change), so expect a
    thin per-version adapter in `src/lib.rs` or separate crates.
  - Have the selector load the matching `caliptra_wasm_demo.js` / `.wasm` and
    defaults, and hide UI that does not apply (e.g. MCU mode on 1.x).
